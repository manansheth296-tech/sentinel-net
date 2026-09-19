"""
SentinelNet — Explainability Engine (backend/explain.py)
=========================================================

Genuine SHAP-based feature attribution for the SIH_LSTM_V4 world model
(canonical implementation: model2/).

WHAT CHANGED FROM THE OLD VERSION
----------------------------------
The previous version of this file computed:

    abs(gradient * input * a hand-written recency weight)

and labeled it "explainability" without ever calling the `shap` package.
That is a custom saliency heuristic, not SHAP, and it is no longer used.

This version wraps the model with `shap.GradientExplainer` (SHAP's
approach for differentiable models such as LSTMs) and, only if that
genuinely fails to run in the current environment, falls back to a
model-agnostic permutation-importance estimate. Every response this
module returns states which method actually produced the numbers in
the "method" field — the UI must display that field verbatim rather
than assuming "SHAP" everywhere.

BACKGROUND DISTRIBUTION — AN HONEST LIMITATION
------------------------------------------------
SHAP methods need a background/reference distribution to measure each
feature's marginal contribution against. This repository does not ship
the original training set, so we cannot use real training data as the
background. Instead, when the uploaded capture produces more than one
temporal window, we use the OTHER windows from the same uploaded file as
the background distribution (a common, defensible practice when a
held-out reference set isn't available). If the uploaded file produces
only a single window (the minimum needed to run the model at all), no
independent background exists and global/whole-session SHAP is reported
as unavailable rather than faked from a background of one.

WHAT THIS MODULE PROVIDES
--------------------------
1. Local explanation    - SHAP values for the current (most recent) prediction.
2. Global explanation   - mean |SHAP| across all windows in the analyzed
                           session, when enough windows exist.
3. Temporal explanation - mean |SHAP| per sequence timestep (20 steps),
                           showing which points in time drove the prediction.
4. Feature aggregation  - the 156 state dimensions (77 raw features x
                           {mean, std} + unique_dst_ports + flow_count) are
                           mapped back to human-readable raw feature names,
                           reporting the mean-contribution and
                           std-contribution (variability) separately as well
                           as combined.
"""

from __future__ import annotations

import warnings
from typing import Dict, List, Optional

import numpy as np
import torch
import torch.nn as nn


class _RiskHeadOnly(nn.Module):
    """SHAP needs a model with a single tensor output; wraps out the
    next-state prediction head and exposes only the attack-risk logit."""

    def __init__(self, model: nn.Module):
        super().__init__()
        self.model = model

    def forward(self, x):
        _, risk_logit = self.model(x)
        return risk_logit.unsqueeze(-1)


def _split_feature_name(col: str):
    if col.endswith("_mean"):
        return col[:-5], "mean"
    if col.endswith("_std"):
        return col[:-4], "std"
    return col, None


def _aggregate_to_raw_features(per_dim_values: np.ndarray, feature_names: List[str]) -> List[Dict]:
    """Collapse a (156,) array of per-state-dimension values back to raw
    network-feature names, keeping the mean/std split visible."""
    agg: Dict[str, Dict[str, float]] = {}
    for idx, col in enumerate(feature_names):
        raw_name, kind = _split_feature_name(col)
        val = float(per_dim_values[idx])
        entry = agg.setdefault(raw_name, {"mean_contribution": 0.0, "std_contribution": 0.0, "other_contribution": 0.0})
        if kind == "mean":
            entry["mean_contribution"] += val
        elif kind == "std":
            entry["std_contribution"] += val
        else:
            entry["other_contribution"] += val

    rows = []
    for raw_name, parts in agg.items():
        combined = parts["mean_contribution"] + parts["std_contribution"] + parts["other_contribution"]
        rows.append({
            "feature": raw_name,
            "mean_contribution": round(parts["mean_contribution"], 6),
            "std_contribution": round(parts["std_contribution"], 6),
            "combined_contribution": round(combined, 6),
        })
    rows.sort(key=lambda r: r["combined_contribution"], reverse=True)
    return rows


def _signed_direction(value: float) -> str:
    if value > 1e-9:
        return "increases attack risk"
    if value < -1e-9:
        return "decreases attack risk"
    return "no measurable effect"


def _permutation_importance(model, sequence, feature_names, device, n_repeats: int = 4) -> np.ndarray:
    """Real, model-agnostic importance estimate batched for fast execution."""
    model.eval()
    seq_len, num_dims = sequence.shape
    with torch.no_grad():
        base_x = torch.from_numpy(sequence.astype(np.float32)).unsqueeze(0).to(device)
        base_prob = float(torch.sigmoid(model(base_x)[1]).item())

        rng = np.random.default_rng(42)
        total_samples = num_dims * n_repeats
        batch = np.repeat(sequence[np.newaxis, :, :], total_samples, axis=0)

        for dim in range(num_dims):
            for r in range(n_repeats):
                idx = dim * n_repeats + r
                batch[idx, :, dim] = rng.permutation(sequence[:, dim])

        x_tensor = torch.from_numpy(batch.astype(np.float32)).to(device)
        _, risk_logits = model(x_tensor)
        probs = torch.sigmoid(risk_logits).squeeze().cpu().numpy().reshape(num_dims, n_repeats)
        impacts = (probs - base_prob).mean(axis=1)

    return impacts



def _run_shap_gradient_explainer(model, sequence, background, device):
    """Runs shap.GradientExplainer against the risk-classification head.
    Returns a (seq_len, input_dim) array of per-timestep, per-dimension
    SHAP values for the single input sequence."""
    import shap  # local import: module still loads if shap is missing

    wrapped = _RiskHeadOnly(model).to(device)
    wrapped.eval()

    bg_tensor = torch.from_numpy(background.astype(np.float32)).to(device)
    x_tensor = torch.from_numpy(sequence.astype(np.float32)).unsqueeze(0).to(device)

    explainer = shap.GradientExplainer(wrapped, bg_tensor)
    raw = explainer.shap_values(x_tensor)

    arr = raw[0] if isinstance(raw, list) else raw
    arr = np.squeeze(np.asarray(arr))  # -> (seq_len, input_dim)

    if arr.ndim != 2 or arr.shape[1] != sequence.shape[1]:
        raise ValueError(f"Unexpected SHAP output shape {arr.shape}; expected (seq_len, {sequence.shape[1]}).")
    return arr


def explain_prediction(
    model: nn.Module,
    sequence: np.ndarray,
    feature_names: List[str],
    background_sequences: Optional[np.ndarray] = None,
    all_window_states: Optional[np.ndarray] = None,
    top_k: int = 10,
    device: str = "cpu",
) -> Dict:
    """
    Full explainability response for one (seq_len, input_dim) sequence.

    background_sequences : optional (N, seq_len, input_dim) array of other
        scaled sequences built from the SAME uploaded session, used as the
        SHAP background distribution. If None or too small (<5), SHAP is
        not attempted and the function falls back to permutation importance.
    all_window_states : optional (N, input_dim) array of every individual
        scaled state vector from the uploaded file - used for the GLOBAL,
        session-wide importance summary, separate from the local
        explanation of the current window.

    Returns a dict: method, local_explanation, temporal_explanation,
    global_explanation.
    """
    model.eval()
    dev = torch.device(device)
    seq_len, input_dim = sequence.shape

    per_dim_shap = None
    have_background = background_sequences is not None and len(background_sequences) >= 5

    if have_background:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                per_dim_shap = _run_shap_gradient_explainer(model, sequence, background_sequences, dev)
            method = "SHAP GradientExplainer (shap library)"
        except BaseException as e:
            print(f"[SentinelNet explain] SHAP GradientExplainer failed: {e}. Falling back to permutation importance.")
            per_dim_shap = None
            method = None

    else:
        method = None

    if per_dim_shap is None:
        flat_impacts = _permutation_importance(model, sequence, feature_names, dev)
        per_dim_shap = np.tile(flat_impacts / seq_len, (seq_len, 1))
        reason = "insufficient background windows in this session" if not have_background else "runtime error, see server log"
        method = f"Permutation Importance (SHAP GradientExplainer unavailable: {reason})"
        temporal_available = False
    else:
        temporal_available = True

    per_dim_abs_local = np.abs(per_dim_shap).sum(axis=0)
    per_dim_signed_local = per_dim_shap.sum(axis=0)

    local_rows_abs = _aggregate_to_raw_features(per_dim_abs_local, feature_names)
    signed_rows = _aggregate_to_raw_features(per_dim_signed_local, feature_names)
    signed_by_name = {r["feature"]: r["combined_contribution"] for r in signed_rows}

    local_explanation = []
    for row in local_rows_abs[:top_k]:
        signed_val = signed_by_name.get(row["feature"], 0.0)
        local_explanation.append({
            "feature": row["feature"],
            "shap_value": round(signed_val, 6),
            "absolute_shap_value": round(row["combined_contribution"], 6),
            "mean_contribution": row["mean_contribution"],
            "std_contribution": row["std_contribution"],
            "direction": _signed_direction(signed_val),
        })

    if temporal_available:
        per_timestep_importance = np.abs(per_dim_shap).sum(axis=1)
        total = per_timestep_importance.sum()
        temporal_explanation = {
            "available": True,
            "steps": [
                {
                    "timestep": int(t - seq_len + 1),
                    "importance": round(float(v), 6),
                    "importance_share": round(float(v / total), 4) if total > 0 else 0.0,
                }
                for t, v in enumerate(per_timestep_importance)
            ],
            "most_influential_timestep": int(int(np.argmax(per_timestep_importance)) - seq_len + 1),
        }
    else:
        temporal_explanation = {
            "available": False,
            "reason": "Per-timestep attribution requires the SHAP GradientExplainer path; "
                      "the permutation-importance fallback only produces a single "
                      "session-level estimate, not a temporal breakdown.",
        }

    global_explanation: Dict = {"available": False, "reason": "Not enough independent windows in this session."}
    if all_window_states is not None and len(all_window_states) >= 5 and method.startswith("SHAP"):
        try:
            import shap
            wrapped = _RiskHeadOnly(model).to(dev)
            wrapped.eval()
            n = len(all_window_states)
            split = max(5, n // 2)
            bg_states = all_window_states[:split]
            fg_states = all_window_states[split:] if n - split >= 1 else all_window_states[:split]

            def _as_seq(states):
                return np.repeat(states[:, np.newaxis, :], seq_len, axis=1)

            bg_tensor = torch.from_numpy(_as_seq(bg_states).astype(np.float32)).to(dev)
            fg_tensor = torch.from_numpy(_as_seq(fg_states).astype(np.float32)).to(dev)

            explainer = shap.GradientExplainer(wrapped, bg_tensor)
            raw = explainer.shap_values(fg_tensor)
            arr = raw[0] if isinstance(raw, list) else raw
            arr = np.asarray(arr).mean(axis=1)  # collapse repeated-timestep dim -> (n_fg, input_dim)
            mean_abs = np.abs(arr).mean(axis=0)

            global_rows = _aggregate_to_raw_features(mean_abs, feature_names)[:top_k]
            global_explanation = {
                "available": True,
                "n_windows_analyzed": int(n),
                "top_features": [
                    {"feature": r["feature"], "mean_absolute_shap": r["combined_contribution"]}
                    for r in global_rows
                ],
            }
        except Exception as e:
            global_explanation = {"available": False, "reason": f"Global SHAP computation failed at runtime: {e}"}

    return {
        "method": method,
        "local_explanation": local_explanation,
        "temporal_explanation": temporal_explanation,
        "global_explanation": global_explanation,
    }


def explain_prediction_simple(
    model: nn.Module,
    sequence: np.ndarray,
    feature_names: List[str],
    background_sequences: Optional[np.ndarray] = None,
    top_k: int = 5,
    device: str = "cpu",
) -> List[Dict]:
    """Backwards-compatible flat top-k feature/importance list (e.g. for a
    dashboard 'Top Risk Drivers' card). Internally reuses explain_prediction()."""
    full = explain_prediction(model, sequence, feature_names, background_sequences=background_sequences, top_k=top_k, device=device)
    rows = full["local_explanation"]
    total = sum(r["absolute_shap_value"] for r in rows) or 1.0
    return [
        {
            "feature": r["feature"],
            "importance": round(r["absolute_shap_value"] / total, 3),
            "direction": r["direction"],
            "method": full["method"],
        }
        for r in rows
    ]

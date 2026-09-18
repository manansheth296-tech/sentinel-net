# backend/shap_explain.py
"""
SentinelNet — Explainability engine (REAL SHAP, with labeled fallback)
=========================================================================

Explains the canonical model's actual attack-risk output (the
infiltration_head logit -> sigmoid), never a surrogate.

Primary method : shap.GradientExplainer on a CPU copy of the model,
                  wrapped so its only output is the attack-risk logit.
Fallback method: multi-repeat permutation importance (same technique
                  already used in model2/inference.py), used only if
                  SHAP raises (unsupported op, shape mismatch, shap not
                  installed, etc). The fallback is ALWAYS labeled as such
                  in the returned dict — it is never presented as SHAP.

Three views are produced from one SHAP call on the analyzed (last) window:
  - LOCAL:    signed per-raw-feature contribution for this one prediction
  - TEMPORAL: how per-feature contribution magnitude varies across the
              20 sequence steps
  - GLOBAL:   mean |SHAP| aggregated across several analyzed windows in
              the uploaded file (not just the last one), giving a
              dataset-level ranking rather than a single-prediction view.

156 -> 77 raw-feature aggregation is deterministic: FEATURE_COLS is laid
out as [<raw_0>_mean, <raw_0>_std, <raw_1>_mean, <raw_1>_std, ...,
unique_dst_ports, flow_count]. For each raw feature we sum the signed SHAP
value of its _mean and _std columns. unique_dst_ports and flow_count are
reported as their own pseudo-features (they are not derived from a single
raw column).
"""

from __future__ import annotations

from typing import List, Optional

import numpy as np

from backend.data_prep import FEATURE_COLS, RAW_FEATURE_NAMES, INPUT_DIM
from backend.model_runtime import TORCH_AVAILABLE, DEVICE, WorldModelLSTM

if TORCH_AVAILABLE:
    import torch
    import torch.nn as nn


# ---------------------------------------------------------------------------
# Deterministic 156 -> 77(+2) raw-feature grouping
# ---------------------------------------------------------------------------
def _raw_feature_groups() -> List[dict]:
    """[{'name': raw_feature_or_pseudo_feature, 'indices': [i, ...]}]
    in a fixed, documented order (77 raw features, then the two
    window-level pseudo-features)."""
    groups = []
    idx = {c: i for i, c in enumerate(FEATURE_COLS)}
    for raw in RAW_FEATURE_NAMES:
        mean_i = idx.get(f"{raw}_mean")
        std_i = idx.get(f"{raw}_std")
        indices = [i for i in (mean_i, std_i) if i is not None]
        groups.append({"name": raw, "indices": indices})
    for pseudo in ("unique_dst_ports", "flow_count"):
        if pseudo in idx:
            groups.append({"name": pseudo, "indices": [idx[pseudo]]})
    return groups


_RAW_GROUPS = _raw_feature_groups()


def _aggregate_to_raw(per_feature_values: np.ndarray) -> List[dict]:
    """per_feature_values: (156,) signed or unsigned values indexed by
    FEATURE_COLS order. Returns one summed value per raw/pseudo feature,
    in the fixed group order."""
    out = []
    for g in _RAW_GROUPS:
        total = float(sum(per_feature_values[i] for i in g["indices"]))
        out.append({"feature": g["name"], "contribution": total})
    return out


# ---------------------------------------------------------------------------
# Fallback: multi-repeat permutation importance (unsigned, magnitude-only)
# ---------------------------------------------------------------------------
def _permutation_importance(model, window: np.ndarray, n_repeats: int = 5, seed: int = 0) -> np.ndarray:
    """Returns (156,) array of mean |delta P(attack)| per state feature,
    averaged over n_repeats random shuffles per feature (a single shuffle
    can land near-zero by chance)."""
    rng = np.random.default_rng(seed)
    model.eval()
    with torch.no_grad():
        base_prob = torch.sigmoid(
            model(torch.from_numpy(window.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
        ).item()
    impacts = np.zeros(window.shape[1])
    for i in range(window.shape[1]):
        diffs = []
        for _ in range(n_repeats):
            perturbed = window.copy()
            perturbed[:, i] = rng.permutation(perturbed[:, i])
            with torch.no_grad():
                p = torch.sigmoid(
                    model(torch.from_numpy(perturbed.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
                ).item()
            diffs.append(abs(p - base_prob))
        impacts[i] = float(np.mean(diffs))
    return impacts


class _InfilOnly(nn.Module if TORCH_AVAILABLE else object):
    """Wraps the dual-head model so SHAP only ever explains the
    attack-risk output — never the state-forecast head."""

    def __init__(self, m):
        super().__init__()
        self.m = m

    def forward(self, x):
        return self.m(x)[1].unsqueeze(-1)


def _run_gradient_shap(model, window: np.ndarray, background_windows: np.ndarray) -> np.ndarray:
    """Returns (seq_len, 156) signed SHAP values for one window, using
    shap.GradientExplainer against the attack-risk head. Raises on any
    failure — caller is responsible for catching and falling back."""
    try:
        import shap  # imported lazily so its absence doesn't break the module
    except (Exception, BaseException, OSError) as e:
        raise RuntimeError(f"SHAP dependency load failed: {e}")

    cpu_model = WorldModelLSTM(input_dim=INPUT_DIM).to("cpu")
    cpu_model.load_state_dict(model.state_dict())
    cpu_model.eval()
    wrapped = _InfilOnly(cpu_model)

    bg = torch.from_numpy(background_windows.astype(np.float32))
    explainer = shap.GradientExplainer(wrapped, bg)
    x = torch.from_numpy(window.astype(np.float32)).unsqueeze(0)

    raw_shap = explainer.shap_values(x)
    arr = raw_shap[0] if isinstance(raw_shap, list) else raw_shap
    arr = np.squeeze(np.array(arr))  # -> (seq_len, 156)
    if arr.ndim != 2 or arr.shape[-1] != len(FEATURE_COLS):
        raise ValueError(f"Unexpected SHAP output shape after squeeze: {arr.shape}")
    return arr


def explain(
    model,
    window: np.ndarray,
    background_windows: Optional[np.ndarray] = None,
    extra_windows_for_global: Optional[np.ndarray] = None,
    top_k: int = 8,
) -> dict:
    """
    window: (seq_len, 156) scaled — the sequence actually fed to the model
        for the current prediction.
    background_windows: (N, seq_len, 156) scaled — background distribution
        for SHAP. If None or too small, SHAP is skipped and the module
        goes straight to the labeled permutation fallback.
    extra_windows_for_global: (M, seq_len, 156) additional analyzed windows
        from the SAME uploaded file (e.g. one per sliding position), used
        to build the GLOBAL view. If None, GLOBAL falls back to the local
        window only (M=1) and is labeled accordingly.

    Returns:
      {
        "method": "SHAP - GradientExplainer" | "Permutation fallback - SHAP unavailable",
        "fallback_reason": str | None,
        "local": {"positive": [...], "negative": [...], "raw_aggregated": [...]},
        "temporal": {"timesteps": [...], "per_timestep_total_abs": [...]},
        "global": {"ranking": [...], "n_windows_analyzed": int, "method": str},
      }
    """
    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch not installed; cannot compute SHAP or fallback importance.")

    method = "SHAP - GradientExplainer"
    fallback_reason = None
    per_timestep_signed = None  # (seq_len, 156) if SHAP succeeded

    have_background = background_windows is not None and len(background_windows) >= 2
    if have_background:
        try:
            per_timestep_signed = _run_gradient_shap(model, window, background_windows)
        except (Exception, BaseException, OSError) as e:  # any SHAP or DLL failure triggers the labeled fallback
            method = "Permutation fallback - SHAP unavailable"
            fallback_reason = f"{type(e).__name__}: {e}"
    else:
        method = "Permutation fallback - SHAP unavailable"
        fallback_reason = "Insufficient background samples for a stable SHAP background distribution."

    if per_timestep_signed is not None:
        # ---- LOCAL (signed, from the real last-timestep-weighted sum) ----
        per_feature_signed = per_timestep_signed.sum(axis=0)  # (156,)
        raw_signed = _aggregate_to_raw(per_feature_signed)
        raw_signed_sorted = sorted(raw_signed, key=lambda r: r["contribution"], reverse=True)
        positive = [r for r in raw_signed_sorted if r["contribution"] > 0][:top_k]
        negative = sorted(
            [r for r in raw_signed_sorted if r["contribution"] < 0], key=lambda r: r["contribution"]
        )[:top_k]

        # ---- TEMPORAL ----
        per_timestep_abs_total = np.abs(per_timestep_signed).sum(axis=1)  # (seq_len,)
        top_feature_per_step = []
        for t in range(per_timestep_signed.shape[0]):
            raw_t = _aggregate_to_raw(per_timestep_signed[t])
            top = max(raw_t, key=lambda r: abs(r["contribution"]))
            top_feature_per_step.append(top["feature"])

        # ---- GLOBAL ----
        if extra_windows_for_global is not None and len(extra_windows_for_global) > 0:
            abs_stack = [np.abs(per_timestep_signed).sum(axis=0)]
            for w in extra_windows_for_global:
                try:
                    other = _run_gradient_shap(model, w, background_windows)
                    abs_stack.append(np.abs(other).sum(axis=0))
                except (Exception, BaseException, OSError):
                    continue
            mean_abs = np.mean(np.stack(abs_stack), axis=0)
            n_windows = len(abs_stack)
            global_method = method
        else:
            mean_abs = np.abs(per_feature_signed)
            n_windows = 1
            global_method = method + " (only the analyzed window was available; not a multi-window aggregate)"

        raw_global = sorted(_aggregate_to_raw(mean_abs), key=lambda r: abs(r["contribution"]), reverse=True)

        # ---- HEATMAP (top-K raw features x seq_len) — only possible when
        # real per-timestep SHAP values are available (i.e. not in the
        # permutation-importance fallback path). Every cell is a real
        # aggregated SHAP value for that feature at that timestep — no
        # interpolation or synthetic fill.
        heat_k = min(top_k, len(_RAW_GROUPS))
        heat_features = [r["feature"] for r in raw_global[:heat_k]]
        heat_values = []
        for feat_name in heat_features:
            group = next(g for g in _RAW_GROUPS if g["name"] == feat_name)
            row = [
                float(sum(per_timestep_signed[t, i] for i in group["indices"]))
                for t in range(per_timestep_signed.shape[0])
            ]
            heat_values.append(row)

        return {
            "method": method,
            "fallback_reason": fallback_reason,
            "local": {
                "positive": positive,
                "negative": negative,
                "raw_aggregated": raw_signed_sorted,
            },
            "temporal": {
                "timesteps": [f"t-{per_timestep_signed.shape[0]-1-i}" for i in range(per_timestep_signed.shape[0])],
                "per_timestep_total_abs_contribution": [float(v) for v in per_timestep_abs_total],
                "top_feature_per_timestep": top_feature_per_step,
            },
            "global": {
                "ranking": raw_global[:top_k],
                "n_windows_analyzed": n_windows,
                "method": global_method,
            },
            "heatmap": {
                "available": True,
                "features": heat_features,
                "timesteps": [f"t-{per_timestep_signed.shape[0]-1-i}" for i in range(per_timestep_signed.shape[0])],
                "values": heat_values,
            },
        }

    # ---------------------------------------------------------------
    # Fallback path — unsigned permutation importance, clearly labeled
    # ---------------------------------------------------------------
    impacts = _permutation_importance(model, window)
    raw_unsigned = sorted(_aggregate_to_raw(impacts), key=lambda r: r["contribution"], reverse=True)

    per_step_impacts = []
    for t in range(window.shape[0]):
        w2 = window.copy()
        # Zero out this single timestep to approximate its marginal effect —
        # a cheap, clearly-labeled temporal proxy (NOT SHAP).
        w2[t, :] = 0.0
        with torch.no_grad():
            base = torch.sigmoid(
                model(torch.from_numpy(window.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
            ).item()
            p = torch.sigmoid(
                model(torch.from_numpy(w2.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
            ).item()
        per_step_impacts.append(abs(base - p))

    return {
        "method": method,
        "fallback_reason": fallback_reason,
        "local": {
            "positive": raw_unsigned[:top_k],
            "negative": [],  # permutation importance is magnitude-only, not signed
            "raw_aggregated": raw_unsigned,
        },
        "temporal": {
            "timesteps": [f"t-{window.shape[0]-1-i}" for i in range(window.shape[0])],
            "per_timestep_total_abs_contribution": per_step_impacts,
            "top_feature_per_timestep": [],
        },
        "global": {
            "ranking": raw_unsigned[:top_k],
            "n_windows_analyzed": 1,
            "method": method,
        },
        "heatmap": {
            "available": False,
            "reason": "Per-timestep feature attribution requires the SHAP GradientExplainer path; the permutation-importance fallback only yields a single per-timestep magnitude, not a per-feature breakdown.",
        },
    }

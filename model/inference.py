"""
model/inference.py — SentinelNet Dhoogla-Checkpoint Inference
=================================================================

Loads world_model_v4_best.pt + scaler_v4.pkl + export_bundle_v4.json and
exposes `predict(file_path)` returning the exact JSON contract CONTRACT.md
expects. This is the ONLY file the backend /predict route should import
from — everything else (preprocessing, model architecture, explainability)
is wired together here.

Model summary
-------------
2-layer LSTM (128 hidden), dual head:
  - state_head:       predicts the next 156-dim state (the "world model" part)
  - infiltration_head: predicts P(attack) for that predicted next state
Input:  (batch, 20, 156)   Output: (next_state (batch,156), logit (batch,))

Test-set numbers for THIS checkpoint (see export_bundle_v4.json):
  F1=0.8354  Precision=0.9278  Recall=0.7597  FPR=0.0172
Report these exact numbers — do not round up or reuse numbers from a
different run.

Known limitations (state these proactively, don't wait to be asked):
  - MITRE stage for HISTORICAL windows is a file-level heuristic (this
    dataset mirror has one attack family per file). For FORECASTED future
    states, stage is assigned by nearest centroid instead (see
    STAGE_CENTROIDS below) since there's no ground-truth label to look up.
  - Target label is generic "any attack", not infiltration-specific.
  - Windowing is 200-row pseudo-windows, not real 10-second time windows
    (using_real_time_windows=False in the bundle).

Do NOT modify world_model_v4_best.pt or scaler_v4.pkl.
"""

from __future__ import annotations

import os
from typing import List, Optional

import numpy as np
import torch
import torch.nn as nn

from preprocessing import (
    FEATURE_COLS,
    SEQ_LEN,
    INPUT_DIM,
    file_to_scaled_sequence,
)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_CKPT_PATH = os.path.join(_THIS_DIR, "world_model_v4_best.pt")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ---------------------------------------------------------------------------
# Model architecture — must match the training notebook exactly, or
# load_state_dict() will fail (or worse, silently load into mismatched shapes)
# ---------------------------------------------------------------------------

class WorldModelLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=128, num_layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim, hidden_size=hidden_dim, num_layers=num_layers,
            batch_first=True, dropout=dropout if num_layers > 1 else 0.0,
        )
        self.norm = nn.LayerNorm(hidden_dim)
        self.state_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden_dim, input_dim),
        )
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden_dim, 64), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(64, 1),
        )

    def forward(self, x):
        out, _ = self.lstm(x)
        last_hidden = self.norm(out[:, -1, :])
        next_state = self.state_head(last_hidden)
        infiltration_logit = self.infiltration_head(last_hidden).squeeze(-1)
        return next_state, infiltration_logit


_model: Optional[WorldModelLSTM] = None


def get_model() -> WorldModelLSTM:
    """Load (once) the checkpoint and return the model in eval mode."""
    global _model
    if _model is None:
        if not os.path.exists(_CKPT_PATH):
            raise FileNotFoundError(
                f"world_model_v4_best.pt not found at {_CKPT_PATH}. "
                "Push it into model/ alongside scaler_v4.pkl and export_bundle_v4.json."
            )
        ckpt = torch.load(_CKPT_PATH, map_location=DEVICE)
        m = WorldModelLSTM(input_dim=ckpt.get("input_dim", INPUT_DIM)).to(DEVICE)
        m.load_state_dict(ckpt["model_state_dict"])
        m.eval()
        _model = m
    return _model


# ---------------------------------------------------------------------------
# MITRE stage for FORECASTED states — nearest-centroid matching against
# per-stage mean state vectors computed from the training set. Historical
# windows use preprocessing.stage_from_filename() instead (ground-truth
# heuristic) — this is only for states the model itself predicted.
# ---------------------------------------------------------------------------

_stage_centroids = None  # lazy: {stage_name: np.ndarray(156,)}


def _load_stage_centroids() -> dict:
    """Loaded from export_bundle_v4.json if present; otherwise computed
    lazily is NOT supported here (centroids require the full train_df,
    which isn't available at inference time) — they must be baked into
    the bundle at export time. Falls back to 'Unknown' if absent."""
    global _stage_centroids
    if _stage_centroids is None:
        import json
        bundle_path = os.path.join(_THIS_DIR, "export_bundle_v4.json")
        with open(bundle_path) as f:
            bundle = json.load(f)
        raw_centroids = bundle.get("stage_centroids")
        if raw_centroids:
            _stage_centroids = {k: np.array(v, dtype=np.float32) for k, v in raw_centroids.items()}
        else:
            _stage_centroids = {}
    return _stage_centroids


def nearest_stage(predicted_state_scaled: np.ndarray) -> str:
    """Map a model-predicted (scaled) next-state vector to the nearest
    MITRE stage centroid. Returns 'Unknown' if centroids weren't exported
    (older bundle) rather than crashing — degrade gracefully in a demo."""
    centroids = _load_stage_centroids()
    if not centroids:
        return "Unknown"
    names = list(centroids.keys())
    dists = [np.linalg.norm(centroids[n] - predicted_state_scaled) for n in names]
    return names[int(np.argmin(dists))]


# ---------------------------------------------------------------------------
# Autoregressive K-step forecast
# ---------------------------------------------------------------------------

def forecast(model: WorldModelLSTM, initial_window: np.ndarray, k_steps: int = 5) -> List[dict]:
    """Roll the model forward k_steps, feeding each predicted state back in
    as the new last timestep. initial_window: (SEQ_LEN, INPUT_DIM) scaled."""
    model.eval()
    window = torch.from_numpy(initial_window.astype(np.float32)).unsqueeze(0).to(DEVICE)
    results = []
    with torch.no_grad():
        for step in range(1, k_steps + 1):
            next_state, infiltration_logit = model(window)
            prob = torch.sigmoid(infiltration_logit).item()
            next_state_np = next_state.squeeze(0).cpu().numpy()
            stage = nearest_stage(next_state_np)
            results.append({
                "step_ahead": step,
                "infiltration_prob": round(prob, 4),
                "predicted_stage": stage,
            })
            window = torch.cat([window[:, 1:, :], next_state.unsqueeze(1)], dim=1)
    return results


# ---------------------------------------------------------------------------
# Explainability — SHAP with a permutation-importance fallback
# ---------------------------------------------------------------------------

def _permutation_importance(model, window, feature_cols, top_k=3, n_repeats=5):
    """Averages multiple random shuffles per feature — a single shuffle can
    land near-zero by chance, especially on a confident prediction."""
    model.eval()
    with torch.no_grad():
        base_prob = torch.sigmoid(
            model(torch.from_numpy(window.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
        ).item()
    impacts = np.zeros(len(feature_cols))
    for i in range(len(feature_cols)):
        diffs = []
        for _ in range(n_repeats):
            perturbed = window.copy()
            perturbed[:, i] = np.random.permutation(perturbed[:, i])
            with torch.no_grad():
                p = torch.sigmoid(
                    model(torch.from_numpy(perturbed.astype(np.float32)).unsqueeze(0).to(DEVICE))[1]
                ).item()
            diffs.append(abs(p - base_prob))
        impacts[i] = np.mean(diffs)
    top_idx = np.argsort(impacts)[::-1][:top_k]
    return [{"feature": feature_cols[i], "contribution": float(impacts[i])} for i in top_idx]


def explain_prediction(model, window, background_windows, feature_cols=None, top_k=3):
    feature_cols = feature_cols or FEATURE_COLS
    model.eval()
    try:
        import shap
        cpu_model = WorldModelLSTM(input_dim=INPUT_DIM).to("cpu")
        cpu_model.load_state_dict(model.state_dict())
        cpu_model.eval()

        class InfilOnly(nn.Module):
            def __init__(self, m):
                super().__init__()
                self.m = m

            def forward(self, x):
                return self.m(x)[1].unsqueeze(-1)

        wrapped = InfilOnly(cpu_model)
        bg = torch.from_numpy(background_windows.astype(np.float32))
        explainer = shap.GradientExplainer(wrapped, bg)
        x = torch.from_numpy(window.astype(np.float32)).unsqueeze(0)

        raw_shap = explainer.shap_values(x)
        arr = raw_shap[0] if isinstance(raw_shap, list) else raw_shap
        arr = np.squeeze(np.array(arr))
        if arr.ndim != 2 or arr.shape[-1] != len(feature_cols):
            raise ValueError(f"Unexpected SHAP output shape after squeeze: {arr.shape}")

        per_feature = np.abs(arr).mean(axis=0)
        top_idx = np.argsort(per_feature)[::-1][:top_k]
        return [{"feature": feature_cols[i], "contribution": float(per_feature[i])} for i in top_idx]
    except Exception as e:
        print(f"[SHAP unavailable/shape mismatch: {e}] Falling back to permutation importance.")
        return _permutation_importance(model, window, feature_cols, top_k)


# ---------------------------------------------------------------------------
# current_stage: majority vote over the last few REAL (observed) windows —
# NOT a single window, which can be a fluke (captures often end with a few
# quiet seconds right after an attack script finishes).
# ---------------------------------------------------------------------------

def _current_stage_from_recent(state_vecs, recent_n: int = 5) -> tuple[str, dict]:
    n = min(recent_n, len(state_vecs))
    recent = state_vecs["mitre_stage"].iloc[-n:]
    mode = recent.mode().iloc[0]
    votes = recent.value_counts().to_dict()
    return mode, votes


# ---------------------------------------------------------------------------
# Public contract function — this is what the backend /predict route calls
# ---------------------------------------------------------------------------

def predict(file_path: str, k_steps: int = 5, background_pool: Optional[np.ndarray] = None) -> dict:
    """
    Run the full pipeline on a raw CIC-IDS-2018-style file and return the
    JSON contract from CONTRACT.md.

    background_pool: optional (N, SEQ_LEN, INPUT_DIM) array of scaled
    training sequences to use as the SHAP background distribution. If not
    provided, explainability falls back straight to permutation importance
    (still correct, just skips the SHAP attempt).
    """
    try:
        last_window, state_vecs = file_to_scaled_sequence(file_path)
    except ValueError as e:
        return {"error": str(e)}

    model = get_model()
    timeline = forecast(model, last_window, k_steps=k_steps)
    current_stage, current_stage_votes = _current_stage_from_recent(state_vecs)

    if background_pool is not None and len(background_pool) > 0:
        idx = np.random.choice(len(background_pool), size=min(60, len(background_pool)), replace=False)
        bg_sample = background_pool[idx]
        top_features = explain_prediction(model, last_window, bg_sample)
    else:
        top_features = _permutation_importance(model, last_window, FEATURE_COLS)

    return {
        "infiltration_timeline": timeline,
        "current_stage": current_stage,
        "current_stage_recent_window_votes": current_stage_votes,
        "top_features": top_features,
    }

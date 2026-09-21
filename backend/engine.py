"""
backend/engine.py — SentinelNet inference orchestration
=========================================================

CANONICAL MODEL DECISION (see docs/MODEL_DECISION.md for the full audit)
--------------------------------------------------------------------------
This repository ships two model directories, model/ and model2/. They are
NOT identical (different checkpoint weights, different preprocessing,
different explainability code, different documented benchmark numbers).

model2/ is used as the canonical implementation because:
  - its export_bundle_v4.json is explicitly marked "FINAL — dhoogla,
    submission version", while model/'s bundle is marked "PROTOTYPE —
    will be retrained once team finalizes cleaned dataset".
  - model2/inference.py already implements a genuine shap.GradientExplainer
    call with a documented, honest permutation-importance fallback; model/
    has no SHAP code at all.
  - model2/export_bundle_v4.json ships stage_centroids used for honest
    nearest-centroid MITRE staging of FORECASTED (not-yet-observed) states.
  - model2/preprocessing.py documents and enforces the known
    unique_dst_ports-always-zero training landmine explicitly.

model/ is left in the repository untouched for reference, but this engine
does not import from it.

WHAT THIS FILE REMOVES FROM THE PREVIOUS VERSION
--------------------------------------------------
  - Hardcoded "flagged_flows" (172.31.69.25 -> 18.218.115.60, etc.) that
    were copied verbatim from docs/CONTRACT.md's *example* payload and
    returned as if they were real detections on every single analysis.
  - Hardcoded "stage_probs" percentages that were never produced by any
    classifier (the model has a single risk logit, not a 5-way stage head).
  - The `except Exception` fallback that silently returned a fake,
    canned "attack detected" result whenever preprocessing or inference
    failed. Failures now surface as real, honest error payloads.
  - Benchmark numbers that were hardcoded a second time in this file and
    had drifted from model2's actual bundle values (0.8403 here vs the
    canonical 0.8354 in model2/export_bundle_v4.json). Benchmarks are now
    read directly from the canonical bundle, once, at import time.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Optional

import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL2_DIR = os.path.join(PROJECT_ROOT, "model2") if os.path.isdir(os.path.join(PROJECT_ROOT, "model2")) else os.path.join(PROJECT_ROOT, "model")

for p in (MODEL2_DIR, CURRENT_DIR, PROJECT_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from .mitre_mapping import get_mitre_stage  # backend/mitre_mapping.py, rule-based lookup
from .explain import explain_prediction, explain_prediction_simple  # backend/explain.py, real SHAP

# model modules
import preprocessing as m2_preprocessing  # noqa: E402
import inference as m2_inference  # noqa: E402

with open(os.path.join(MODEL2_DIR, "export_bundle_v4.json")) as _f:
    _BUNDLE = json.load(_f)


BENCHMARK_SOURCE = "model2/export_bundle_v4.json (recorded test-set evaluation from training run)"
WORLD_MODEL_BENCHMARK = {
    "f1": _BUNDLE.get("test_f1"),
    "precision": _BUNDLE.get("test_precision"),
    "recall": _BUNDLE.get("test_recall"),
    "fpr": _BUNDLE.get("test_fpr"),
}
MODEL_STATUS = _BUNDLE.get("status", "unknown")

# Optional: a real logistic-regression baseline computed by
# backend/train_baseline.py --output-json <path>. Never fabricated here —
# only loaded if the file genuinely exists on disk.
_BASELINE_PATH = os.environ.get(
    "SENTINELNET_BASELINE_JSON",
    os.path.join(CURRENT_DIR, "baseline_result.json"),
)


def _load_logistic_baseline() -> Dict:
    if os.path.exists(_BASELINE_PATH):
        try:
            with open(_BASELINE_PATH) as f:
                data = json.load(f)
            data_dir = data.get("data_dir", "unknown")
            sample_frac = data.get("sample_frac", None)
            frac_pct = f"{int(sample_frac * 100)}%" if sample_frac is not None else "unknown"
            caveat = (
                f"Computed on 3 sample CSV files from '{data_dir}' at {frac_pct} row sampling — "
                "not the full CIC-IDS-2018 dataset. These numbers are a small-sample estimate "
                "only; do not compare them directly to the World Model recorded benchmark above, "
                "which was evaluated on a full held-out test set."
            )
            return {
                "available": True,
                "f1": data.get("f1"), "precision": data.get("precision"),
                "recall": data.get("recall"), "fpr": data.get("fpr"),
                "source": f"Recorded run of backend/train_baseline.py, cached at {_BASELINE_PATH}",
                "data_dir": data_dir,
                "sample_frac": sample_frac,
                "caveat": caveat,
            }
        except Exception as e:
            return {"available": False, "reason": f"Found {_BASELINE_PATH} but could not parse it: {e}"}
    return {
        "available": False,
        "reason": "No cached baseline result is bundled with this repository. Run "
                  "backend/train_baseline.py --output-json "
                  f"{_BASELINE_PATH} to generate a real baseline from the bundled sample CSVs.",
    }

KNOWN_LIMITATIONS = [
    "The model predicts a generic 'any attack' risk score, not a proven infiltration-specific classification.",
    "Temporal windows are 200-row pseudo-windows (using_real_time_windows=False in the export bundle), "
    "not genuine real-time 10-second windows.",
    "unique_dst_ports is forced to 0.0 at both training and inference time (see model2/preprocessing.py) "
    "because the training data source had no usable destination-port column. The model has never learned "
    "a meaningful signal from destination-port diversity.",
    "MITRE ATT&CK staging for historical windows is a rule-based, file/label heuristic "
    "(backend/mitre_mapping.py / model2 stage_from_filename), not a learned classifier. Staging for "
    "FORECASTED future windows uses nearest-centroid matching against per-stage training centroids, "
    "which is also not a probabilistic classifier.",
    f"Checkpoint status recorded in the export bundle: '{MODEL_STATUS}'.",
]

_engine_state: Dict = {}


def get_engine() -> Dict:
    """Load (once) the canonical model2 model + scaler + constants."""
    if not _engine_state:
        _engine_state["model"] = m2_inference.get_model()
        _engine_state["scaler"] = m2_preprocessing.get_scaler()
        _engine_state["feature_cols"] = m2_preprocessing.FEATURE_COLS
        _engine_state["seq_len"] = m2_preprocessing.SEQ_LEN
        _engine_state["input_dim"] = m2_preprocessing.INPUT_DIM
    return _engine_state


def _build_background_sequences(all_scaled: np.ndarray, seq_len: int, target_window: np.ndarray) -> Optional[np.ndarray]:
    """
    Build alternate (seq_len, input_dim) sequences from the SAME uploaded
    session to use as a SHAP background distribution, excluding the exact
    target window. Returns None if the session doesn't have enough extra
    windows to form an independent background (SHAP is then skipped
    honestly rather than run against a degenerate background).
    """
    n = len(all_scaled)
    if n <= seq_len:
        return None
    candidates = []
    for start in range(0, n - seq_len):
        window = all_scaled[start:start + seq_len]
        if np.allclose(window, target_window):
            continue
        candidates.append(window)
    if len(candidates) < 5:
        return None
    # Cap background size for speed; SHAP GradientExplainer cost scales with it.
    if len(candidates) > 40:
        idx = np.linspace(0, len(candidates) - 1, 40).astype(int)
        candidates = [candidates[i] for i in idx]
    return np.stack(candidates, axis=0)


def _majority_recent_stage(state_vecs, recent_n: int = 5) -> Dict:
    n = min(recent_n, len(state_vecs))
    recent = state_vecs["mitre_stage"].iloc[-n:]
    mode = recent.mode()
    mode_val = str(mode.iloc[0]) if len(mode) else "Unknown"
    votes = {str(k): int(v) for k, v in recent.value_counts().to_dict().items()}
    return {"stage": mode_val, "votes_over_last_n_windows": votes, "n_windows_considered": int(n)}


def _extract_flow_preview(file_path: str, max_rows: int = 500) -> Dict:
    """
    Real flow rows from the uploaded file for the Network Flows page.
    NOTE: the model scores 200-row AGGREGATE windows, not individual flows,
    so per-flow risk cannot be honestly reported — only which window a flow
    belongs to and that window's aggregate risk (once known) can be shown.
    """
    import pandas as pd

    try:
        raw = m2_preprocessing.load_raw_file(file_path)
    except Exception as e:
        return {"available": False, "reason": f"Could not re-read uploaded file for flow preview: {e}"}

    raw.columns = [str(c).strip() for c in raw.columns]
    candidate_cols = {
        "src_ip": m2_preprocessing._find_col(raw.columns, ["src ip", "source ip"]),
        "dst_ip": m2_preprocessing._find_col(raw.columns, ["dst ip", "destination ip"]),
        "src_port": m2_preprocessing._find_col(raw.columns, ["src port", "source port"]),
        "dst_port": m2_preprocessing._find_col(raw.columns, ["dst port", "destination port"]),
        "protocol": m2_preprocessing._find_col(raw.columns, ["protocol"]),
        "flow_duration": m2_preprocessing._find_col(raw.columns, ["flow duration"]),
        "label": m2_preprocessing._find_col(raw.columns, ["label"]),
    }
    present = {k: v for k, v in candidate_cols.items() if v is not None}
    if not present:
        return {"available": False, "reason": "No recognizable flow-identifier columns (Src IP, Dst IP, ports, etc.) in the uploaded file."}

    window_rows = m2_preprocessing.WINDOW_ROWS
    n_rows = min(len(raw), max_rows)
    rows = []
    for i in range(n_rows):
        row = raw.iloc[i]
        entry = {k: (None if pd.isna(row[col]) else row[col]) for k, col in present.items()}
        entry["row_index"] = int(i)
        entry["window_id"] = int(i // window_rows)
        rows.append(entry)

    return {
        "available": True,
        "columns_found": list(present.keys()),
        "window_rows": window_rows,
        "note": "Risk scores are computed per aggregate window, not per individual flow. "
                "Match window_id to the analyzed window index to see that window's aggregate context.",
        "rows": rows,
        "total_rows_in_file": int(len(raw)),
        "rows_shown": n_rows,
    }


def to_jsonable(obj):
    """Recursively convert numpy types, infinities, and NaNs to standard JSON types."""
    if isinstance(obj, dict):
        return {
            (str(k) if isinstance(k, (np.integer, np.floating, np.ndarray)) else k): to_jsonable(v)
            for k, v in obj.items()
        }
    elif isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32, np.float16, float)):
        if np.isnan(obj) or np.isinf(obj):
            return 0.0
        return float(obj)
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return to_jsonable(obj.tolist())
    return obj


def run_inference(file_path: str) -> Dict:
    """
    Main entrypoint for the SentinelNet backend / API layer.

    Returns a structured, honest response. On failure, returns
    {"error": True, "message": ..., "stage": ...} instead of fabricated
    "successful" attack data.
    """
    try:
        engine = get_engine()
        model = engine["model"]
        scaler = engine["scaler"]
        feature_cols = engine["feature_cols"]
        seq_len = engine["seq_len"]
    except Exception as e:
        return {"error": True, "stage": "model_loading", "message": f"Failed to load model/scaler: {e}"}

    # 1. Preprocess
    try:
        last_window, state_vecs = m2_preprocessing.file_to_scaled_sequence(file_path)
    except ValueError as e:
        return {"error": True, "stage": "preprocessing", "message": str(e)}
    except Exception as e:
        return {"error": True, "stage": "preprocessing", "message": f"Unexpected preprocessing failure: {e}"}

    try:
        vecs_to_scale = (
            state_vecs[feature_cols]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .clip(-1e9, 1e9)
            .astype(np.float32)
        )
        all_scaled = scaler.transform(vecs_to_scale).astype(np.float32)
        all_scaled = np.nan_to_num(all_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    except Exception as e:
        return {"error": True, "stage": "preprocessing", "message": f"Failed to scale state vectors: {e}"}

    # 2. Current prediction
    import torch
    try:
        with torch.no_grad():
            x = torch.from_numpy(last_window.astype(np.float32)).unsqueeze(0)
            _, risk_logit = model(x)
            current_probability = float(torch.sigmoid(risk_logit).item())
    except Exception as e:
        return {"error": True, "stage": "inference", "message": f"Model forward pass failed: {e}"}

    # 3. Forecast (real autoregressive rollout + nearest-centroid staging)
    try:
        timeline_raw = m2_inference.forecast(model, last_window, k_steps=5)
    except Exception as e:
        return {"error": True, "stage": "forecast", "message": f"Forecast rollout failed: {e}"}

    # 4. Historical stage (rule-based, honestly labeled) + rule-based MITRE lookup
    recent_stage_info = _majority_recent_stage(state_vecs)
    dataset_style_label = recent_stage_info["stage"]
    mitre_lookup = get_mitre_stage(dataset_style_label)

    # 5. Explainability — real SHAP where the session supports it
    background_sequences = _build_background_sequences(all_scaled, seq_len, last_window)
    explanation = explain_prediction(
        model=model,
        sequence=last_window,
        feature_names=feature_cols,
        background_sequences=background_sequences,
        all_window_states=all_scaled,
        top_k=10,
    )
    top_features_simple = explain_prediction_simple(
        model=model, sequence=last_window, feature_names=feature_cols,
        background_sequences=background_sequences, top_k=5,
    )

    # 6. Flow preview (no fabricated per-flow risk)
    flows = _extract_flow_preview(file_path)

    res = {
        "prediction": {
            "attack_risk_probability": round(current_probability, 4),
            "predicted_attack": bool(current_probability >= 0.5),
            "threshold": 0.5,
        },
        "current_context": {
            "recent_stage": recent_stage_info,
            "rule_based_mitre_stage": mitre_lookup,
            "mitre_mapping_type": "rule-based lookup table (backend/mitre_mapping.py), not a learned classifier",
        },
        "forecast": timeline_raw,
        "forecast_note": "Each forecast step is an autoregressive model rollout; predicted_stage in each "
                          "step comes from nearest-centroid distance to training-set stage centroids, "
                          "not a probability, and 'window' spacing follows the 200-row pseudo-window "
                          "contract rather than a real 10-second clock.",
        "shap": explanation,
        "top_features": top_features_simple,
        "flows": flows,
        "benchmark": {
            "world_model": WORLD_MODEL_BENCHMARK,
            "world_model_source": BENCHMARK_SOURCE,
            "logistic_baseline": _load_logistic_baseline(),
        },
        "metadata": {
            "model_version": "SIH_LSTM_V4",
            "canonical_source": "model2/",
            "sequence_shape": [seq_len, engine["input_dim"]],
            "windows_in_session": int(len(state_vecs)),
            "using_real_time_windows": bool(m2_preprocessing.USING_REAL_TIME),
            "window_rows": int(m2_preprocessing.WINDOW_ROWS),
        },
        "limitations": KNOWN_LIMITATIONS,
        "status": MODEL_STATUS,
    }
    return to_jsonable(res)


"""
model/preprocessing.py — SentinelNet Dhoogla-Checkpoint Preprocessing
=======================================================================

Single source of truth for turning a raw CIC-IDS-2018 file into the exact
(20, 156) sequence the LSTM world model expects. Every constant here is
derived from export_bundle_v4.json at import time — never hardcoded — so
this file automatically stays in sync with whichever checkpoint sits in
this directory.

Pipeline
--------
Raw CICFlowMeter file (CSV/Parquet)
  → detect numeric feature columns + label column
  → clean (inf -> NaN -> drop), attach is_attack
  → 200-row pseudo-windows (this checkpoint: using_real_time_windows=False)
  → per-window: mean(77) + std(77) + unique_dst_ports + flow_count = 156-D
  → scaler_v4.pkl.transform()   (fit on TRAIN ONLY — never refit here)
  → last SEQ_LEN consecutive states → (SEQ_LEN, 156) LSTM input tensor

⚠️ KNOWN LANDMINE — unique_dst_ports
-------------------------------------
The dhoogla mirror this model was trained on has NO destination-port
column, so `unique_dst_ports` was ALWAYS 0.0 for every training window.
The model has never seen this feature be anything else. If you swap in a
raw source that DOES have a real Dst Port column, this module still forces
the feature to 0.0 (see `_ALWAYS_ZERO_PORT_FEATURE` below) to match the
training distribution. Do not remove that override without retraining.

Do NOT modify export_bundle_v4.json or scaler_v4.pkl by hand.
"""

from __future__ import annotations

import gc
import json
import os
from typing import List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Locate bundle/scaler relative to this file — works from model/ or project root
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BUNDLE_PATH = os.path.join(_THIS_DIR, "export_bundle_v4.json")
_SCALER_PATH = os.path.join(_THIS_DIR, "scaler_v4.pkl")


def _load_bundle() -> dict:
    if not os.path.exists(_BUNDLE_PATH):
        raise FileNotFoundError(
            f"export_bundle_v4.json not found at {_BUNDLE_PATH}. "
            "Copy it into model/ alongside world_model_v4_best.pt and scaler_v4.pkl."
        )
    with open(_BUNDLE_PATH) as f:
        return json.load(f)


_BUNDLE = _load_bundle()

# 156 state feature names, in exact training order — single source of truth
FEATURE_COLS: List[str] = list(_BUNDLE["feature_cols"])
SEQ_LEN: int = int(_BUNDLE["seq_len"])
INPUT_DIM: int = int(_BUNDLE["input_dim"])
WINDOW_ROWS: int = int(_BUNDLE.get("window_rows", 200))
USING_REAL_TIME: bool = bool(_BUNDLE.get("using_real_time_windows", False))

assert len(FEATURE_COLS) == INPUT_DIM, (
    f"FEATURE_COLS ({len(FEATURE_COLS)}) does not match INPUT_DIM ({INPUT_DIM})."
)

# 77 raw feature names, derived in-order from FEATURE_COLS (strip "_mean" suffix,
# skip the two non-raw-derived columns). Never hardcode this count — it changes
# whenever the underlying dataset schema does.
RAW_FEATURE_NAMES: List[str] = [
    c[:-5]
    for c in FEATURE_COLS
    if c not in ("unique_dst_ports", "flow_count") and c.endswith("_mean")
]
_expected_raw = (INPUT_DIM - 2) // 2
assert len(RAW_FEATURE_NAMES) == _expected_raw, (
    f"Expected {_expected_raw} raw features (derived from INPUT_DIM={INPUT_DIM}), "
    f"got {len(RAW_FEATURE_NAMES)}. FEATURE_COLS naming convention may have broken."
)

# This checkpoint was trained with unique_dst_ports ALWAYS 0.0 (dhoogla mirror has
# no usable Dst Port column). Force it here too so inference matches training —
# see the module docstring landmine note. Flip to False only after retraining
# with real port data.
_ALWAYS_ZERO_PORT_FEATURE: bool = True

_scaler = None  # lazy-loaded singleton


def get_scaler():
    """Load (once) and return the StandardScaler fit on TRAIN data only.
    Never call .fit() on this scaler — only .transform()."""
    global _scaler
    if _scaler is None:
        if not os.path.exists(_SCALER_PATH):
            raise FileNotFoundError(
                f"scaler_v4.pkl not found at {_SCALER_PATH}. "
                "Push scaler_v4.pkl (NOT scaler.pkl) into model/."
            )
        _scaler = joblib.load(_SCALER_PATH)
    return _scaler


# ---------------------------------------------------------------------------
# Raw file loading + schema detection
# ---------------------------------------------------------------------------

def load_raw_file(path: str, columns: Optional[List[str]] = None) -> pd.DataFrame:
    """Load a raw CICFlowMeter CSV or Parquet file."""
    if path.endswith(".parquet"):
        return pd.read_parquet(path, columns=columns)
    return pd.read_csv(path, usecols=columns, low_memory=False)


def _find_col(columns, keywords: List[str]) -> Optional[str]:
    for kw in keywords:
        for c in columns:
            if kw.lower() in c.lower():
                return c
    return None


def detect_schema(df: pd.DataFrame) -> dict:
    """Detect label/timestamp/dst-port columns and the numeric feature set
    present in an arbitrary raw file. Used for sanity-checking a new file
    against RAW_FEATURE_NAMES before running it through the pipeline."""
    label_col = _find_col(df.columns, ["label"])
    timestamp_col = _find_col(df.columns, ["timestamp", "time stamp"])
    dst_port_col = _find_col(df.columns, ["dst port", "destination port"])
    if label_col is None:
        raise ValueError("Could not find a label column in the input file.")
    non_feature = {label_col, timestamp_col, dst_port_col}
    numeric_cols = [
        c for c in df.columns
        if c not in non_feature and pd.api.types.is_numeric_dtype(df[c])
    ]
    return {
        "label_col": label_col,
        "timestamp_col": timestamp_col,
        "dst_port_col": dst_port_col,
        "numeric_cols": numeric_cols,
    }


# ---------------------------------------------------------------------------
# MITRE ATT&CK stage — file-level heuristic (dhoogla mirror has one attack
# family per file, so the filename IS the ground-truth attack category).
# NOTE: this is a heuristic for HISTORICAL/labeled data, not a model output.
# For FORECASTED future states, inference.py uses nearest-centroid matching
# instead (see STAGE_CENTROIDS in inference.py).
# ---------------------------------------------------------------------------

FILE_TAG_TO_STAGE = {
    "bruteforce": "Credential Access / Initial Access",
    "dos":        "Impact",
    "ddos":       "Impact",
    "web":        "Initial Access",
    "infil":      "Lateral Movement",
    "botnet":     "Command & Control",
}


def stage_from_filename(tag: str, is_attack: int) -> str:
    if not is_attack:
        return "Benign"
    key = tag.lower()
    for k, v in FILE_TAG_TO_STAGE.items():
        if k in key:
            return v
    return "Unknown"


# ---------------------------------------------------------------------------
# State-vector construction — MUST exactly match the training-time logic
# ---------------------------------------------------------------------------

def build_state_vectors(
    d: pd.DataFrame,
    file_tag: str,
    numeric_cols: List[str],
    label_col: str,
    dst_port_col: Optional[str],
) -> pd.DataFrame:
    """One file's flows -> one row per WINDOW_ROWS-sized bucket of flows.
    156-dim state = mean(77) + std(77) + unique_dst_ports + flow_count.
    Uses pandas .agg(['mean','std']) — ddof=1 — matching the training notebook
    exactly. Do not switch to numpy's ddof=0 default."""
    d = d.reset_index(drop=True)
    if "is_attack" not in d.columns:
        d["is_attack"] = (d[label_col].astype(str).str.lower() != "benign").astype(int)
    d["window_id"] = np.arange(len(d)) // WINDOW_ROWS

    agg_dict = {c: ["mean", "std"] for c in numeric_cols}
    grouped = d.groupby("window_id").agg(agg_dict)
    grouped.columns = ["_".join(c) for c in grouped.columns]
    grouped = grouped.fillna(0.0).astype(np.float32)

    if dst_port_col is not None and not _ALWAYS_ZERO_PORT_FEATURE:
        grouped["unique_dst_ports"] = d.groupby("window_id")[dst_port_col].nunique().astype(np.float32)
    else:
        # Forced to 0.0 — see module docstring landmine note.
        grouped["unique_dst_ports"] = np.float32(0.0)

    grouped["is_attack"] = d.groupby("window_id")["is_attack"].max()
    grouped["flow_count"] = d.groupby("window_id").size().astype(np.float32)
    grouped["mitre_stage"] = grouped.apply(
        lambda row: stage_from_filename(file_tag, row["is_attack"]), axis=1
    )
    grouped["source_file"] = file_tag

    return grouped.sort_index().reset_index(drop=True)


def clean_and_prepare(raw: pd.DataFrame, label_col: str, numeric_cols: List[str]) -> pd.DataFrame:
    """Inf -> NaN -> drop, cast to float32, attach is_attack. Matches training
    cleaning exactly (no silent NaN->0 here — rows with bad values are dropped,
    same as in the training notebook)."""
    raw = raw.copy()
    for c in numeric_cols:
        raw[c] = pd.to_numeric(raw[c], errors="coerce").astype(np.float32)
    raw[numeric_cols] = raw[numeric_cols].replace([np.inf, -np.inf], np.nan)
    raw = raw.dropna(subset=numeric_cols).reset_index(drop=True)
    raw["is_attack"] = (raw[label_col].astype(str).str.lower() != "benign").astype(int) \
        if label_col in raw.columns else 0
    gc.collect()
    return raw


def _raw_feature_intersection(numeric_cols_in_file: List[str]) -> List[str]:
    """Restrict a file's detected numeric columns down to exactly the 77 raw
    feature names this model was trained on, preserving RAW_FEATURE_NAMES
    order (order matters for scaler.transform() consistency)."""
    available = set(numeric_cols_in_file)
    return [c for c in RAW_FEATURE_NAMES if c in available]


def file_to_scaled_sequence(file_path: str) -> Tuple[np.ndarray, pd.DataFrame]:
    """End-to-end: raw file path -> (last SEQ_LEN, 156) scaled array ready
    for the model, plus the full (unscaled) state_vecs DataFrame for stage
    lookups / diagnostics.

    Raises ValueError if the file doesn't produce at least SEQ_LEN windows.
    """
    raw = load_raw_file(file_path)
    schema = detect_schema(raw)
    numeric_cols = _raw_feature_intersection(schema["numeric_cols"])
    if not numeric_cols:
        # fall back to whatever numeric columns are present, best-effort
        numeric_cols = schema["numeric_cols"]

    cleaned = clean_and_prepare(raw, schema["label_col"], numeric_cols)
    tag = os.path.basename(file_path)
    state_vecs = build_state_vectors(
        cleaned, tag, numeric_cols, schema["label_col"], schema["dst_port_col"]
    )

    if len(state_vecs) < SEQ_LEN:
        raise ValueError(
            f"Need at least {SEQ_LEN} windows for one sequence, got {len(state_vecs)}. "
            "File is too short — needs at least SEQ_LEN * WINDOW_ROWS flow records."
        )

    scaler = get_scaler()
    x_scaled = scaler.transform(state_vecs[FEATURE_COLS]).astype(np.float32)
    last_window = x_scaled[-SEQ_LEN:]
    return last_window, state_vecs

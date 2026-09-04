"""
backend/data_prep.py — SentinelNet V4 Data Preprocessing Pipeline
==================================================================

Single source of truth for all raw CSV cleaning and state-vector construction.

Pipeline
--------
Raw CICFlowMeter CSV
  → strip/normalise column names
  → remove repeated header rows
  → keep the 77 raw numeric model features + optional metadata columns
  → pd.to_numeric(errors="coerce")
  → NaN / ±Inf → 0   (team-agreed cleaning rule)
  → 200-row temporal windows  (V4 checkpoint: using_real_time_windows=False)
    fallback to 10-second timestamp windows when the checkpoint flag is True
  → per-window: mean(77) + std(77) + unique_dst_ports + flow_count = 156-D
  → scaler_v4.pkl.transform()  (never fit on demo/test data)
  → last 20 consecutive states → (20, 156) LSTM input tensor

Ground-truth sources
--------------------
  feature_cols  : export_bundle_v4.json   → 156 state features
  raw features  : infer_raw_feature_names() from feature_cols  → 77 names
  seq_len       : export_bundle_v4.json   → 20
  input_dim     : export_bundle_v4.json   → 156
  windowing     : export_bundle_v4.json   → using_real_time_windows=False
  scaler        : scaler_v4.pkl           → StandardScaler fitted on TRAIN only
  ddof for std  : grouped.agg(std)        → pandas default ddof=1
                  (matches V4 notebook: df.groupby().agg("std"))

Do NOT modify world_model_v4_best.pt or scaler_v4.pkl.
"""

from __future__ import annotations

import os
import json
from typing import List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Locate model-directory artifacts relative to this file.
# This works whether the module is imported from project root or from backend/.
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
_MODEL_DIR = os.path.join(_PROJECT_ROOT, "model")

_BUNDLE_PATH = os.path.join(_MODEL_DIR, "export_bundle_v4.json")
_SCALER_PATH = os.path.join(_MODEL_DIR, "scaler_v4.pkl")

# ---------------------------------------------------------------------------
# V4 constants — loaded once from the export bundle (single source of truth)
# ---------------------------------------------------------------------------
def _load_bundle() -> dict:
    if not os.path.exists(_BUNDLE_PATH):
        raise FileNotFoundError(
            f"V4 export bundle not found at {_BUNDLE_PATH}. "
            "Copy export_bundle_v4.json into model/ before running."
        )
    with open(_BUNDLE_PATH) as f:
        return json.load(f)


_BUNDLE = _load_bundle()

# 156 state feature names in exact V4 order
FEATURE_COLS: List[str] = list(_BUNDLE["feature_cols"])

# 77 raw CICFlowMeter feature names, in the order the bundle expects
RAW_FEATURE_NAMES: List[str] = [
    c[:-5]                                          # strip "_mean"
    for c in FEATURE_COLS
    if c not in ("unique_dst_ports", "flow_count") and c.endswith("_mean")
]

SEQ_LEN: int = int(_BUNDLE["seq_len"])              # 20
INPUT_DIM: int = int(_BUNDLE["input_dim"])          # 156
WINDOW_ROWS: int = 200                              # rows-per-bucket fallback
WINDOW_SECONDS: int = 10                            # seconds-per-bucket (real-time mode)
USING_REAL_TIME: bool = bool(
    _BUNDLE.get("using_real_time_windows", False)
)                                                   # False for current V4 weights

assert len(FEATURE_COLS) == INPUT_DIM, (
    f"FEATURE_COLS ({len(FEATURE_COLS)}) does not match INPUT_DIM ({INPUT_DIM})."
)
assert len(RAW_FEATURE_NAMES) == 77, (
    f"Expected 77 raw features, got {len(RAW_FEATURE_NAMES)}."
)

# ---------------------------------------------------------------------------
# CICFlowMeter column-name normalisation map
# Many public CIC-IDS-2018 CSVs use slightly different header spellings.
# Keys are lower-stripped incoming names; values are the canonical V4 names.
# ---------------------------------------------------------------------------
_COL_ALIASES: dict = {
    # Packet counts
    "tot fwd pkts":              "Total Fwd Packets",
    "total fwd packets":         "Total Fwd Packets",
    "tot bwd pkts":              "Total Backward Packets",
    "total backward packets":    "Total Backward Packets",
    # Packet length totals
    "totlen fwd pkts":           "Fwd Packets Length Total",
    "fwd packets length total":  "Fwd Packets Length Total",
    "totlen bwd pkts":           "Bwd Packets Length Total",
    "bwd packets length total":  "Bwd Packets Length Total",
    # Rate features — alternate slashes/spaces
    "flow byts/s":               "Flow Bytes/s",
    "flow bytes/s":              "Flow Bytes/s",
    "flow pkts/s":               "Flow Packets/s",
    "flow packets/s":            "Flow Packets/s",
    "fwd pkts/s":                "Fwd Packets/s",
    "fwd packets/s":             "Fwd Packets/s",
    "bwd pkts/s":                "Bwd Packets/s",
    "bwd packets/s":             "Bwd Packets/s",
    # Header lengths
    "fwd header len":            "Fwd Header Length",
    "fwd header length":         "Fwd Header Length",
    "bwd header len":            "Bwd Header Length",
    "bwd header length":         "Bwd Header Length",
    # Packet-length stats
    "pkt len min":               "Packet Length Min",
    "packet length min":         "Packet Length Min",
    "pkt len max":               "Packet Length Max",
    "packet length max":         "Packet Length Max",
    "pkt len mean":              "Packet Length Mean",
    "packet length mean":        "Packet Length Mean",
    "pkt len std":               "Packet Length Std",
    "packet length std":         "Packet Length Std",
    "pkt len var":               "Packet Length Variance",
    "packet length var":         "Packet Length Variance",
    "packet length variance":    "Packet Length Variance",
    # Flags
    "fin flag cnt":              "FIN Flag Count",
    "fin flag count":            "FIN Flag Count",
    "syn flag cnt":              "SYN Flag Count",
    "syn flag count":            "SYN Flag Count",
    "rst flag cnt":              "RST Flag Count",
    "rst flag count":            "RST Flag Count",
    "psh flag cnt":              "PSH Flag Count",
    "psh flag count":            "PSH Flag Count",
    "ack flag cnt":              "ACK Flag Count",
    "ack flag count":            "ACK Flag Count",
    "urg flag cnt":              "URG Flag Count",
    "urg flag count":            "URG Flag Count",
    "cwe flag cnt":              "CWE Flag Count",
    "cwe flag count":            "CWE Flag Count",
    "ece flag cnt":              "ECE Flag Count",
    "ece flag count":            "ECE Flag Count",
    # Size averages
    "pkt size avg":              "Avg Packet Size",
    "avg packet size":           "Avg Packet Size",
    "fwd seg size avg":          "Avg Fwd Segment Size",
    "avg fwd segment size":      "Avg Fwd Segment Size",
    "bwd seg size avg":          "Avg Bwd Segment Size",
    "avg bwd segment size":      "Avg Bwd Segment Size",
    # Bulk features
    "fwd byts/b avg":            "Fwd Avg Bytes/Bulk",
    "fwd avg bytes/bulk":        "Fwd Avg Bytes/Bulk",
    "fwd pkts/b avg":            "Fwd Avg Packets/Bulk",
    "fwd avg pkts/bulk":         "Fwd Avg Packets/Bulk",
    "fwd avg packets/bulk":      "Fwd Avg Packets/Bulk",
    "fwd blk rate avg":          "Fwd Avg Bulk Rate",
    "fwd avg bulk rate":         "Fwd Avg Bulk Rate",
    "bwd byts/b avg":            "Bwd Avg Bytes/Bulk",
    "bwd avg bytes/bulk":        "Bwd Avg Bytes/Bulk",
    "bwd pkts/b avg":            "Bwd Avg Packets/Bulk",
    "bwd avg pkts/bulk":         "Bwd Avg Packets/Bulk",
    "bwd avg packets/bulk":      "Bwd Avg Packets/Bulk",
    "bwd blk rate avg":          "Bwd Avg Bulk Rate",
    "bwd avg bulk rate":         "Bwd Avg Bulk Rate",
    # Packet length stats (abbreviated)
    "fwd pkt len max":           "Fwd Packet Length Max",
    "fwd pkt len min":           "Fwd Packet Length Min",
    "fwd pkt len mean":          "Fwd Packet Length Mean",
    "fwd pkt len std":           "Fwd Packet Length Std",
    "bwd pkt len max":           "Bwd Packet Length Max",
    "bwd pkt len min":           "Bwd Packet Length Min",
    "bwd pkt len mean":          "Bwd Packet Length Mean",
    "bwd pkt len std":           "Bwd Packet Length Std",
    # IAT Totals
    "fwd iat tot":               "Fwd IAT Total",
    "bwd iat tot":               "Bwd IAT Total",
    # Subflow
    "subflow fwd pkts":          "Subflow Fwd Packets",
    "subflow fwd packets":       "Subflow Fwd Packets",
    "subflow fwd byts":          "Subflow Fwd Bytes",
    "subflow fwd bytes":         "Subflow Fwd Bytes",
    "subflow bwd pkts":          "Subflow Bwd Packets",
    "subflow bwd packets":       "Subflow Bwd Packets",
    "subflow bwd byts":          "Subflow Bwd Bytes",
    "subflow bwd bytes":         "Subflow Bwd Bytes",
    # Init window bytes
    "init fwd win byts":         "Init Fwd Win Bytes",
    "init fwd win bytes":        "Init Fwd Win Bytes",
    "init bwd win byts":         "Init Bwd Win Bytes",
    "init bwd win bytes":        "Init Bwd Win Bytes",
    # Active/data packets
    "fwd act data pkts":         "Fwd Act Data Packets",
    "fwd act data packets":      "Fwd Act Data Packets",
    "fwd seg size min":          "Fwd Seg Size Min",
    # Dst port
    "dst port":                  "Dst Port",
    "destination port":          "Dst Port",
}

# Non-feature metadata columns to exclude from the 77-feature model input
_METADATA_COLS = frozenset(
    {"Label", "Timestamp", "Dst Port", "Flow ID", "Src IP", "Dst IP", "Src Port",
     "label", "timestamp", "dst port", "flow id", "src ip", "dst ip", "src port"}
)


# ---------------------------------------------------------------------------
# Step 1: Load raw CSV
# ---------------------------------------------------------------------------
def load_raw_csv(path: str) -> pd.DataFrame:
    """
    Load a CICFlowMeter CSV.

    Handles:
    - UTF-8 with BOM
    - Trailing whitespace in column names
    - low_memory=False to avoid mixed-type warnings on large files
    """
    df = pd.read_csv(path, low_memory=False, encoding="utf-8-sig")
    df.columns = df.columns.str.strip()
    return df


# ---------------------------------------------------------------------------
# Step 2: Normalise column names
# ---------------------------------------------------------------------------
def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map alternate CICFlowMeter column spellings to the canonical V4 names.
    Operates case-insensitively; preserves columns that need no mapping.
    """
    rename_map = {}
    for col in df.columns:
        key = col.strip().lower()
        if key in _COL_ALIASES:
            rename_map[col] = _COL_ALIASES[key]
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


# ---------------------------------------------------------------------------
# Step 3: Remove repeated header rows
# ---------------------------------------------------------------------------
def remove_repeated_headers(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICFlowMeter sometimes appends the header row as a data row.

    A row is a repeated header if any model-feature column value equals
    the column name string.  We detect this by checking whether the
    Dst Port (or any feature column that should be numeric) contains
    a string equal to its own column name.

    Strategy: try to coerce the *first* raw model feature to numeric;
    rows that parse to NaN via coerce AND whose string value is a
    known column name are headers.
    """
    if len(df) == 0:
        return df

    # Use the first raw feature as the sentinel
    sentinel = RAW_FEATURE_NAMES[0]   # "Protocol"

    if sentinel not in df.columns:
        # Can't detect via sentinel; fall back to Dst Port heuristic
        if "Dst Port" in df.columns:
            mask = df["Dst Port"].astype(str).str.strip() == "Dst Port"
            return df[~mask].reset_index(drop=True)
        return df

    mask = df[sentinel].astype(str).str.strip() == sentinel
    return df[~mask].reset_index(drop=True)


# ---------------------------------------------------------------------------
# Step 4: Find metadata columns
# ---------------------------------------------------------------------------
def _find_col(columns, keywords: List[str]) -> Optional[str]:
    """Return the first column whose name contains any of the keywords."""
    for kw in keywords:
        for c in columns:
            if kw.lower() in str(c).lower():
                return c
    return None


def detect_metadata_cols(df: pd.DataFrame) -> dict:
    """
    Auto-detect optional metadata columns present in the dataframe.
    Returns a dict of role -> column_name (or None).
    """
    return {
        "label":       _find_col(df.columns, ["label"]),
        "timestamp":   _find_col(df.columns, ["timestamp", "time stamp", "time_stamp"]),
        "dst_port":    _find_col(df.columns, ["dst port", "destination port"]),
        "attack_type": _find_col(df.columns, ["attack type", "attack_type",
                                               "category", "sub label", "sub-label"]),
        "src_ip":      _find_col(df.columns, ["src ip", "source ip"]),
        "dst_ip":      _find_col(df.columns, ["dst ip", "destination ip"]),
        "flow_id":     _find_col(df.columns, ["flow id", "flow_id"]),
    }


# ---------------------------------------------------------------------------
# Step 5: Clean numeric features
# ---------------------------------------------------------------------------
def clean_numeric_features(
    df: pd.DataFrame,
    raw_feature_names: List[str] = RAW_FEATURE_NAMES,
) -> pd.DataFrame:
    """
    Team-agreed cleaning rule for model features:

        pd.to_numeric(errors="coerce")  → NaN for non-parseable values
        NaN  → 0
        +Inf → 0
        -Inf → 0

    A row is NOT dropped merely because one feature value is NaN/Inf;
    it is replaced with 0 and the row is kept.

    Actual numeric 0.0 values are preserved unchanged.

    Post-condition:
        df[raw_feature_names].isna().sum().sum() == 0
        np.isinf(df[raw_feature_names].values).sum() == 0
    """
    missing = [c for c in raw_feature_names if c not in df.columns]
    if missing:
        raise ValueError(
            f"Input CSV is missing {len(missing)} required model-feature columns. "
            f"First missing: {missing[:5]}"
        )

    for col in raw_feature_names:
        df[col] = (
            pd.to_numeric(df[col], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .astype(np.float32)
        )

    # Hard assertions — should never fail after the above steps
    assert df[raw_feature_names].isna().sum().sum() == 0, \
        "NaN values remain after cleaning — this is a bug."
    assert not np.isinf(df[raw_feature_names].values).any(), \
        "Inf values remain after cleaning — this is a bug."

    return df


# ---------------------------------------------------------------------------
# Step 6: Build is_attack label (no leakage — only used for metadata output)
# ---------------------------------------------------------------------------
def _attach_is_attack(df: pd.DataFrame, label_col: Optional[str]) -> pd.DataFrame:
    if label_col is not None and label_col in df.columns:
        df["is_attack"] = (
            df[label_col].astype(str).str.strip().str.lower() != "benign"
        ).astype(np.int8)
    else:
        df["is_attack"] = np.int8(0)
    return df


# ---------------------------------------------------------------------------
# Step 7: Temporal windowing
# ---------------------------------------------------------------------------
def assign_window_ids(
    df: pd.DataFrame,
    timestamp_col: Optional[str],
    use_real_time: bool = USING_REAL_TIME,
) -> pd.DataFrame:
    """
    Assign a window_id to each row.

    Real-time mode  (use_real_time=True):
      - Parse Timestamp column
      - Sort chronologically
      - bucket = floor(unix_epoch / WINDOW_SECONDS)  [10-second windows]

    Fallback mode   (use_real_time=False, current V4 weights):
      - Preserve existing row order
      - bucket = row_index // WINDOW_ROWS  [200-row windows]

    The V4 export bundle records using_real_time_windows=False,
    meaning current weights were trained with row-bucket windows.
    Switching to real-time mode requires retraining.
    """
    df = df.reset_index(drop=True)

    if use_real_time:
        if timestamp_col is None or timestamp_col not in df.columns:
            raise ValueError(
                "use_real_time=True requires a Timestamp column, "
                f"but none was found. Pass use_real_time=False or "
                "supply a CSV that includes a Timestamp column."
            )
        df[timestamp_col] = pd.to_datetime(
            df[timestamp_col], errors="coerce", dayfirst=True
        )
        n_bad = df[timestamp_col].isna().sum()
        if n_bad > 0:
            # Drop rows whose timestamp is unparseable (rare malformed entries)
            df = df.dropna(subset=[timestamp_col]).reset_index(drop=True)

        df = df.sort_values(timestamp_col).reset_index(drop=True)
        df["window_id"] = (
            df[timestamp_col].astype("int64") // 10**9 // WINDOW_SECONDS
        )
    else:
        # Row-bucket windowing — preserves chronological file order without
        # requiring a parseable timestamp.  This is how V4 was trained.
        df["window_id"] = np.arange(len(df)) // WINDOW_ROWS

    return df


# ---------------------------------------------------------------------------
# Step 8: Aggregate windows → 156-D state vectors
# ---------------------------------------------------------------------------
def aggregate_windows(
    df: pd.DataFrame,
    raw_feature_names: List[str] = RAW_FEATURE_NAMES,
    dst_port_col: Optional[str] = None,
    label_col: Optional[str] = None,
    attack_type_col: Optional[str] = None,
) -> pd.DataFrame:
    """
    Convert windowed flow records into 156-D state-vector rows.

    State layout (matches V4 feature_cols order from export_bundle_v4.json):
      Interleaved pairs:
        [0]  Protocol_mean
        [1]  Protocol_std
        [2]  Flow Duration_mean
        [3]  Flow Duration_std
        … (one mean/std pair per raw feature, 77 pairs = 154 columns)
        [154] unique_dst_ports
        [155] flow_count

      NOTE: The V4 export bundle uses interleaved mean/std (not 77 means
      then 77 stds).  reorder_to_v4() enforces the exact FEATURE_COLS order
      so the scaler receives features in the correct layout regardless of what
      order groupby.agg produces them.

    ddof for std: pandas groupby.agg("std") defaults to ddof=1,
    which matches the V4 notebook.  The V4 preprocessing.py also uses
    pandas groupby.agg(["mean","std"]) — same ddof=1.

    NaN std values (e.g., windows with only one row) are filled with 0.0
    to maintain the team-agreed NaN→0 rule.
    """
    agg_dict = {c: ["mean", "std"] for c in raw_feature_names}
    grouped = df.groupby("window_id", sort=True).agg(agg_dict)

    # Flatten MultiIndex columns: (col, stat) → "col_stat"
    grouped.columns = [f"{c}_{stat}" for c, stat in grouped.columns]
    grouped = grouped.fillna(0.0).astype(np.float32)

    # unique_dst_ports
    if dst_port_col is not None and dst_port_col in df.columns:
        grouped["unique_dst_ports"] = (
            df.groupby("window_id")[dst_port_col]
            .nunique()
            .astype(np.float32)
        )
    else:
        grouped["unique_dst_ports"] = np.float32(0.0)

    # flow_count
    grouped["flow_count"] = (
        df.groupby("window_id").size().astype(np.float32)
    )

    # Metadata for downstream display (not model features)
    grouped["is_attack"] = df.groupby("window_id")["is_attack"].max()

    if attack_type_col is not None and attack_type_col in df.columns:
        def _majority_stage(s):
            from collections import Counter
            vals = [v for v in s if str(v).strip().lower() != "benign"]
            if not vals:
                return "Benign"
            return Counter(vals).most_common(1)[0][0]

        grouped["mitre_stage"] = (
            df.groupby("window_id")[attack_type_col].apply(_majority_stage)
        )
    else:
        grouped["mitre_stage"] = "Unknown"

    return grouped.sort_index().reset_index(drop=True)


# ---------------------------------------------------------------------------
# Step 9: Enforce exact V4 feature column order
# ---------------------------------------------------------------------------
def reorder_to_v4(state_df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure state_df has exactly the 156 columns in the order FEATURE_COLS
    expects, so scaler.transform() receives the correct feature layout.
    """
    missing = [c for c in FEATURE_COLS if c not in state_df.columns]
    if missing:
        raise ValueError(
            f"State dataframe is missing {len(missing)} V4 feature columns. "
            f"First missing: {missing[:5]}"
        )
    return state_df[FEATURE_COLS]


# ---------------------------------------------------------------------------
# Step 10: Scale with V4 scaler (never fit on demo data)
# ---------------------------------------------------------------------------
def load_scaler(scaler_path: str = _SCALER_PATH):
    """Load the V4 StandardScaler.  Call once; cache the result."""
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(
            f"V4 scaler not found at {scaler_path}. "
            "Copy scaler_v4.pkl into model/ before running."
        )
    return joblib.load(scaler_path)


def scale_states(
    state_df_156: pd.DataFrame,
    scaler,
) -> np.ndarray:
    """
    Apply the pre-fitted V4 StandardScaler to the (N, 156) state matrix.

    NEVER fit or partial_fit the scaler here.
    Returns float32 array of shape (N, 156).
    """
    expected_features = scaler.n_features_in_
    if state_df_156.shape[1] != expected_features:
        raise ValueError(
            f"Scaler expects {expected_features} features; "
            f"got {state_df_156.shape[1]}."
        )
    return scaler.transform(state_df_156).astype(np.float32)


# ---------------------------------------------------------------------------
# Step 11: Build the (20, 156) LSTM input sequence
# ---------------------------------------------------------------------------
def build_sequence(
    scaled_states: np.ndarray,
    seq_len: int = SEQ_LEN,
) -> np.ndarray:
    """
    Take the last seq_len scaled states to form the LSTM input.

    If fewer than seq_len windows exist, raise a descriptive error.
    Returns shape (seq_len, 156).
    """
    n = len(scaled_states)
    if n < seq_len:
        raise ValueError(
            f"Need at least {seq_len} temporal windows for the LSTM sequence, "
            f"but the input produced only {n} window(s). "
            "Upload a larger traffic capture (at least "
            f"{seq_len * WINDOW_ROWS} flow rows when using row-bucket windowing)."
        )
    return scaled_states[-seq_len:]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def preprocess(
    raw_csv_path: str,
    scaler=None,
    use_real_time: Optional[bool] = None,
    seq_len: int = SEQ_LEN,
    raw_feature_names: List[str] = RAW_FEATURE_NAMES,
    feature_cols: List[str] = FEATURE_COLS,
) -> dict:
    """
    Main entry-point.

    Accepts a raw CICFlowMeter CSV path and returns a dict containing:

      sequence          : np.ndarray (seq_len, 156)  — LSTM input
      state_vectors_scaled : np.ndarray (N, 156)     — all scaled windows
      state_df          : pd.DataFrame               — unscaled state rows
      metadata          : list[dict]                 — per-window context
      schema            : dict                       — pipeline audit info

    Typical caller::

        from backend.data_prep import preprocess
        result = preprocess("uploads/capture.csv")
        sequence = result["sequence"]   # shape (20, 156), ready for LSTM

    engine.py::

        from backend.data_prep import preprocess, load_scaler
        scaler = load_scaler()
        result = preprocess(file_path, scaler=scaler)

    Parameters
    ----------
    raw_csv_path : str
        Path to a raw CICFlowMeter CSV file.
    scaler : sklearn.preprocessing.StandardScaler, optional
        Pre-loaded V4 scaler.  Loaded from model/ if not provided.
    use_real_time : bool, optional
        Override the windowing mode detected from the bundle.
        Default: read from export_bundle_v4.json (currently False).
    seq_len : int
        LSTM sequence length (default 20 from bundle).
    raw_feature_names : list[str]
        77 raw feature names (default: from bundle).
    feature_cols : list[str]
        156 state feature names (default: from bundle).
    """
    if scaler is None:
        scaler = load_scaler()
    if use_real_time is None:
        use_real_time = USING_REAL_TIME

    # 1. Load
    df = load_raw_csv(raw_csv_path)

    # 2. Normalise column names (handle alternate CICFlowMeter spellings)
    df = normalise_columns(df)

    # 3. Remove repeated header rows
    df = remove_repeated_headers(df)

    if len(df) == 0:
        raise ValueError("CSV is empty after removing repeated headers.")

    # 4. Detect metadata columns
    meta = detect_metadata_cols(df)

    # 5. Validate and clean numeric features
    df = clean_numeric_features(df, raw_feature_names)

    # 6. Attach is_attack label (metadata-only, no leakage)
    df = _attach_is_attack(df, meta["label"])

    # 7. Assign window IDs
    df = assign_window_ids(df, meta["timestamp"], use_real_time=use_real_time)

    # 8. Aggregate to state vectors
    state_df = aggregate_windows(
        df,
        raw_feature_names=raw_feature_names,
        dst_port_col=meta["dst_port"],
        label_col=meta["label"],
        attack_type_col=meta["attack_type"],
    )

    # 9. Reorder to exact V4 column order
    state_df_156 = reorder_to_v4(state_df)

    # 10. Scale (never fit)
    scaled = scale_states(state_df_156, scaler)

    # 11. Build LSTM sequence
    sequence = build_sequence(scaled, seq_len=seq_len)

    assert sequence.shape == (seq_len, len(feature_cols)), (
        f"Unexpected sequence shape {sequence.shape}; "
        f"expected ({seq_len}, {len(feature_cols)})."
    )

    # Assemble per-window metadata for the Streamlit UI
    metadata = []
    for i in range(len(state_df)):
        row = state_df.iloc[i]
        metadata.append({
            "window_index":    i,
            "is_attack":       int(row.get("is_attack", 0)),
            "mitre_stage":     str(row.get("mitre_stage", "Unknown")),
            "flow_count":      float(row["flow_count"]),
            "unique_dst_ports": float(row["unique_dst_ports"]),
        })

    return {
        "sequence":              sequence,
        "state_vectors_scaled":  scaled,
        "state_df":              state_df,
        "metadata":              metadata,
        "schema": {
            "label_col":          meta["label"],
            "timestamp_col":      meta["timestamp"],
            "dst_port_col":       meta["dst_port"],
            "attack_type_col":    meta["attack_type"],
            "raw_feature_count":  len(raw_feature_names),
            "state_feature_count": len(feature_cols),
            "seq_len":            seq_len,
            "window_rows":        WINDOW_ROWS,
            "window_seconds":     WINDOW_SECONDS,
            "using_real_time":    use_real_time,
            "n_input_rows":       len(df),
            "n_windows":          len(state_df),
        },
    }


def preprocess_dataframe(
    df: pd.DataFrame,
    scaler=None,
    use_real_time: Optional[bool] = None,
    seq_len: int = SEQ_LEN,
) -> dict:
    """
    Variant of preprocess() that accepts an already-loaded DataFrame.
    Useful for offline dataset processing where the caller controls loading.
    Applies the same full pipeline from step 2 onward.
    """
    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False
    ) as tmp:
        df.to_csv(tmp.name, index=False)
        tmp_path = tmp.name
    try:
        return preprocess(tmp_path, scaler=scaler, use_real_time=use_real_time,
                          seq_len=seq_len)
    finally:
        os.unlink(tmp_path)

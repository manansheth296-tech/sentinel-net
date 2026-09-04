
"""
SIH LSTM V4 — preprocessing.py

Standalone preprocessing for the V4 World-Model LSTM.

Pipeline:
raw CSV/Parquet
    -> clean numeric flow features
    -> chronological 10-second windows
    -> mean/std for the 77 raw numeric features
    -> unique_dst_ports + flow_count
    -> 156-dimensional state vector
    -> StandardScaler fitted on training data
    -> 20 consecutive states => (20, 156)

Important:
- The scaler must be the V4 scaler fitted on TRAIN ONLY.
- Raw feature order is recovered from the saved V4 checkpoint's feature_cols.
- Dst Port is NOT used as a raw model feature; it is used only to derive
  unique_dst_ports.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from datetime import datetime
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import torch


WINDOW_SECONDS = 10
WINDOW_ROWS = 200
SEQ_LEN = 20

MITRE_STAGE_TABLE = {
    "benign": "Benign",
    "portscan": "Reconnaissance",
    "port scan": "Reconnaissance",
    "ftp-bruteforce": "Credential Access / Initial Access",
    "ftp bruteforce": "Credential Access / Initial Access",
    "ssh-bruteforce": "Credential Access / Initial Access",
    "ssh bruteforce": "Credential Access / Initial Access",
    "brute force": "Credential Access / Initial Access",
    "web attack": "Initial Access",
    "sql injection": "Initial Access",
    "xss": "Initial Access",
    "infiltration": "Lateral Movement",
    "bot": "Command & Control",
    "botnet": "Command & Control",
    "dos": "Impact",
    "ddos": "Impact",
    "hulk": "Impact",
    "goldeneye": "Impact",
    "slowloris": "Impact",
    "loic": "Impact",
    "hoic": "Impact",
}


def mitre_stage_for_label(label_text: str) -> str:
    """Rule-based, case-insensitive dataset-label -> MITRE stage mapping."""
    if label_text is None:
        return "Unknown"
    key = str(label_text).strip().lower()
    if key in MITRE_STAGE_TABLE:
        return MITRE_STAGE_TABLE[key]
    for k, v in MITRE_STAGE_TABLE.items():
        if k in key:
            return v
    return "Unknown"


def load_table(path: str) -> pd.DataFrame:
    """Load a CSV or Parquet file."""
    path = str(path)
    if path.lower().endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def find_col(columns, keywords):
    """Find the first column containing one of the supplied keywords."""
    for kw in keywords:
        for c in columns:
            if kw.lower() in str(c).lower():
                return c
    return None


def infer_raw_feature_names(feature_cols: List[str]) -> List[str]:
    """
    Recover the raw feature names from the saved 156-D state feature list.

    Expected V4 state features:
      <raw_feature>_mean
      <raw_feature>_std
      unique_dst_ports
      flow_count
    """
    raw = []
    for c in feature_cols:
        if c in ("unique_dst_ports", "flow_count"):
            continue
        if c.endswith("_mean"):
            raw.append(c[:-5])
    if not raw:
        raise ValueError(
            "Could not recover raw feature names from checkpoint feature_cols."
        )
    return raw


def clean_raw_dataframe(
    df: pd.DataFrame,
    raw_feature_names: List[str],
    label_col: str | None = None,
    timestamp_col: str | None = None,
    dst_port_col: str | None = None,
    attack_type_col: str | None = None,
) -> pd.DataFrame:
    """
    Clean raw flow records using the same numeric/NaN/Inf policy as V4.

    Repeated CSV headers are coerced to NaN and removed by dropna.
    """
    required = list(raw_feature_names)

    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(
            f"Input is missing {len(missing)} required numeric feature columns. "
            f"Examples: {missing[:10]}"
        )

    keep = list(raw_feature_names)
    for c in [label_col, timestamp_col, dst_port_col, attack_type_col]:
        if c is not None and c in df.columns and c not in keep:
            keep.append(c)

    d = df[keep].copy()

    for c in raw_feature_names:
        d[c] = pd.to_numeric(d[c], errors="coerce").astype(np.float32)

    d[raw_feature_names] = d[raw_feature_names].replace(
        [np.inf, -np.inf], np.nan
    )
    d = d.dropna(subset=raw_feature_names).reset_index(drop=True)

    if label_col is not None and label_col in d.columns:
        d["is_attack"] = (
            d[label_col].astype(str).str.strip().str.lower() != "benign"
        ).astype(int)
    else:
        d["is_attack"] = 0

    return d


def build_state_vectors(
    d: pd.DataFrame,
    raw_feature_names: List[str],
    timestamp_col: str | None,
    dst_port_col: str | None,
    attack_type_col: str | None,
    use_real_time: bool = True,
) -> pd.DataFrame:
    """
    Convert raw flow records into V4 state vectors.

    Real-time mode:
      floor(timestamp / 10 seconds) -> window_id

    Fallback mode:
      200 rows -> one window

    State:
      77 means + 77 stds + unique_dst_ports + flow_count = 156 dims.
    """
    d = d.reset_index(drop=True).copy()

    if use_real_time:
        if timestamp_col is None or timestamp_col not in d.columns:
            raise ValueError(
                "V4 contract expects real 10-second timestamp windows, "
                "but no usable timestamp column was provided."
            )

        d[timestamp_col] = pd.to_datetime(
            d[timestamp_col], errors="coerce", dayfirst=True
        )
        d = d.dropna(subset=[timestamp_col]).sort_values(
            timestamp_col
        ).reset_index(drop=True)

        # Same 10-second epoch-bucket logic used in the V4 notebook.
        d["window_id"] = (
            d[timestamp_col].astype("int64") // 10**9 // WINDOW_SECONDS
        )
    else:
        d["window_id"] = np.arange(len(d)) // WINDOW_ROWS

    if len(d) == 0:
        raise ValueError("No valid rows remain after timestamp/feature cleaning.")

    agg_dict = {c: ["mean", "std"] for c in raw_feature_names}
    grouped = d.groupby("window_id").agg(agg_dict)
    grouped.columns = [f"{c}_{stat}" for c, stat in grouped.columns]
    grouped = grouped.fillna(0.0).astype(np.float32)

    if dst_port_col is not None and dst_port_col in d.columns:
        grouped["unique_dst_ports"] = (
            d.groupby("window_id")[dst_port_col]
            .nunique()
            .astype(np.float32)
        )
    else:
        grouped["unique_dst_ports"] = np.float32(0.0)

    grouped["is_attack"] = d.groupby("window_id")["is_attack"].max()
    grouped["flow_count"] = (
        d.groupby("window_id").size().astype(np.float32)
    )

    if attack_type_col is not None and attack_type_col in d.columns:
        def majority_stage(s):
            vals = [
                v for v in s
                if str(v).strip().lower() != "benign"
            ]
            if not vals:
                return "Benign"
            most_common = Counter(vals).most_common(1)[0][0]
            return mitre_stage_for_label(most_common)

        grouped["mitre_stage"] = (
            d.groupby("window_id")[attack_type_col].apply(majority_stage)
        )
        grouped["is_infiltration"] = (
            grouped["mitre_stage"] == "Lateral Movement"
        ).astype(int)
    else:
        grouped["mitre_stage"] = "Unknown"
        # This is the same honest proxy used in V4 when no attack-type label exists.
        grouped["is_infiltration"] = grouped["is_attack"]

    return grouped.sort_index().reset_index(drop=True)


def state_vectors_to_sequence(
    state_df: pd.DataFrame,
    feature_cols: List[str],
    scaler,
    seq_len: int = SEQ_LEN,
) -> Tuple[np.ndarray, np.ndarray, List[dict]]:
    """
    Scale the 156-D state vectors and construct the latest 20-step sequence.

    Returns:
      sequence: (20, 156)
      scaled_states: (num_windows, 156)
      metadata: per-window metadata for downstream display
    """
    missing = [c for c in feature_cols if c not in state_df.columns]
    if missing:
        raise ValueError(f"State dataframe is missing features: {missing[:10]}")

    scaled = scaler.transform(
        state_df[feature_cols]
    ).astype(np.float32)

    if len(scaled) < seq_len:
        raise ValueError(
            f"Need at least {seq_len} temporal windows; got {len(scaled)}."
        )

    metadata = []
    for i in range(len(state_df)):
        row = state_df.iloc[i]
        metadata.append(
            {
                "window_index": i,
                "is_attack": int(row["is_attack"]),
                "mitre_stage": str(row["mitre_stage"]),
                "flow_count": float(row["flow_count"]),
                "unique_dst_ports": float(row["unique_dst_ports"]),
            }
        )

    return scaled[-seq_len:], scaled, metadata


def preprocess_file(
    file_path: str,
    feature_cols: List[str],
    scaler,
    seq_len: int = SEQ_LEN,
    use_real_time: bool = True,
):
    """
    Main standalone entrypoint for raw CSV/Parquet -> LSTM input.

    Returns a dictionary containing:
      sequence       -> (20, 156) float32 array
      state_vectors  -> all scaled states
      metadata       -> window metadata
      state_df       -> unscaled state dataframe
      schema         -> detected column names
    """
    raw = load_table(file_path)

    label_col = find_col(raw.columns, ["label"])
    timestamp_col = find_col(
        raw.columns, ["timestamp", "time stamp", "time_stamp"]
    )
    dst_port_col = find_col(
        raw.columns, ["dst port", "destination port"]
    )
    attack_type_col = find_col(
        raw.columns,
        ["attack type", "attack_type", "category", "sub label", "sub-label"],
    )

    raw_feature_names = infer_raw_feature_names(feature_cols)

    # Preserve the V4 contract: Dst Port is not a raw model feature.
    d = clean_raw_dataframe(
        raw,
        raw_feature_names=raw_feature_names,
        label_col=label_col,
        timestamp_col=timestamp_col,
        dst_port_col=dst_port_col,
        attack_type_col=attack_type_col,
    )

    state_df = build_state_vectors(
        d,
        raw_feature_names=raw_feature_names,
        timestamp_col=timestamp_col,
        dst_port_col=dst_port_col,
        attack_type_col=attack_type_col,
        use_real_time=use_real_time,
    )

    sequence, scaled_states, metadata = state_vectors_to_sequence(
        state_df,
        feature_cols=feature_cols,
        scaler=scaler,
        seq_len=seq_len,
    )

    if sequence.shape != (seq_len, len(feature_cols)):
        raise ValueError(
            f"Unexpected sequence shape {sequence.shape}; "
            f"expected {(seq_len, len(feature_cols))}."
        )

    return {
        "sequence": sequence,
        "state_vectors_scaled": scaled_states,
        "state_df": state_df,
        "metadata": metadata,
        "schema": {
            "label_col": label_col,
            "timestamp_col": timestamp_col,
            "dst_port_col": dst_port_col,
            "attack_type_col": attack_type_col,
            "raw_feature_count": len(raw_feature_names),
            "state_feature_count": len(feature_cols),
            "seq_len": seq_len,
            "window_seconds": WINDOW_SECONDS,
            "using_real_time": use_real_time,
        },
    }


if __name__ == "__main__":
    print("SIH LSTM V4 preprocessing module loaded.")

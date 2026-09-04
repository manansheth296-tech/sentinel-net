"""
data/clean_dataset.py — Offline CIC-IDS-2018 Dataset Cleaner
=============================================================

Reads raw CICFlowMeter CSVs from data/raw/ and writes cleaned,
model-ready flow-level CSVs to data/clean/.

The cleaned output contains:
  - exactly the 77 raw numeric model features in V4 order
  - optional metadata columns: Timestamp, Dst Port, Label, is_attack
  - no repeated header rows
  - no NaN or Inf values

This is the Data team's standard cleaning pass.  The cleaned files can be:
  1. Handed to the model team for retraining.
  2. Used by preprocess() in backend/data_prep.py for offline inference.

Usage
-----
  # Clean all CSVs in data/raw/
  python data/clean_dataset.py

  # Clean a specific file
  python data/clean_dataset.py --input data/raw/03-01-2018.csv

  # Override output directory
  python data/clean_dataset.py --output data/clean_custom/

  # Preview without writing (dry run)
  python data/clean_dataset.py --dry-run
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time

import numpy as np
import pandas as pd

# Allow `from backend.data_prep import ...` when run from project root
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.data_prep import (
    RAW_FEATURE_NAMES,
    FEATURE_COLS,
    load_raw_csv,
    normalise_columns,
    remove_repeated_headers,
    clean_numeric_features,
    detect_metadata_cols,
    _attach_is_attack,
)

_DEFAULT_RAW_DIR = os.path.join(_PROJECT_ROOT, "data", "raw")
_DEFAULT_CLEAN_DIR = os.path.join(_PROJECT_ROOT, "data", "clean")

# Metadata columns to preserve alongside model features in the cleaned output
_PRESERVE_META = ["Timestamp", "Dst Port", "Label", "is_attack"]


def clean_single_file(
    input_path: str,
    output_path: str,
    dry_run: bool = False,
    verbose: bool = True,
) -> dict:
    """
    Clean one raw CICFlowMeter CSV → write to output_path.

    Returns a summary dict with counts.
    """
    t0 = time.time()
    filename = os.path.basename(input_path)
    if verbose:
        print(f"[clean] {filename}")

    # Load
    df = load_raw_csv(input_path)
    raw_rows = len(df)

    # Normalise column names
    df = normalise_columns(df)

    # Remove repeated headers
    df = remove_repeated_headers(df)
    after_header_drop = len(df)
    headers_removed = raw_rows - after_header_drop

    # Detect metadata
    meta = detect_metadata_cols(df)
    
    # Clean numeric features (NaN/Inf → 0)
    df = clean_numeric_features(df, RAW_FEATURE_NAMES)

    # Attach is_attack label
    df = _attach_is_attack(df, meta["label"])

    # Build output: model features + metadata columns that exist
    out_cols = list(RAW_FEATURE_NAMES)
    for col in _PRESERVE_META:
        if col in df.columns and col not in out_cols:
            out_cols.append(col)

    out_df = df[out_cols]

    # Verify post-conditions
    nan_count = out_df[RAW_FEATURE_NAMES].isna().sum().sum()
    inf_count = int(np.isinf(
        out_df[RAW_FEATURE_NAMES].values.astype(float)
    ).sum())

    assert nan_count == 0, f"NaN count after cleaning = {nan_count}"
    assert inf_count == 0, f"Inf count after cleaning = {inf_count}"

    elapsed = time.time() - t0
    summary = {
        "file": filename,
        "raw_rows": raw_rows,
        "headers_removed": headers_removed,
        "clean_rows": len(out_df),
        "model_feature_cols": len(RAW_FEATURE_NAMES),
        "nan_count": int(nan_count),
        "inf_count": int(inf_count),
        "elapsed_s": round(elapsed, 2),
    }

    if verbose:
        print(
            f"  Raw rows:         {raw_rows:,}\n"
            f"  Headers removed:  {headers_removed}\n"
            f"  Clean rows:       {len(out_df):,}\n"
            f"  NaN remaining:    {nan_count}\n"
            f"  Inf remaining:    {inf_count}\n"
            f"  Elapsed:          {elapsed:.2f}s"
        )

    if not dry_run:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        out_df.to_csv(output_path, index=False)
        if verbose:
            print(f"  → Saved: {output_path}\n")
    else:
        if verbose:
            print(f"  [dry-run] Would save: {output_path}\n")

    return summary


def clean_directory(
    raw_dir: str = _DEFAULT_RAW_DIR,
    clean_dir: str = _DEFAULT_CLEAN_DIR,
    dry_run: bool = False,
) -> list[dict]:
    """
    Clean all *.csv files in raw_dir and write them to clean_dir.
    """
    csv_files = sorted(glob.glob(os.path.join(raw_dir, "*.csv")))
    if not csv_files:
        print(f"[clean_dataset] No CSV files found in {raw_dir}")
        return []

    print(f"[clean_dataset] Found {len(csv_files)} file(s) in {raw_dir}")
    summaries = []
    for path in csv_files:
        out_name = os.path.splitext(os.path.basename(path))[0] + "_clean.csv"
        out_path = os.path.join(clean_dir, out_name)
        summary = clean_single_file(path, out_path, dry_run=dry_run)
        summaries.append(summary)

    total_raw = sum(s["raw_rows"] for s in summaries)
    total_clean = sum(s["clean_rows"] for s in summaries)
    print(
        f"\n[clean_dataset] Done.\n"
        f"  Total raw rows:   {total_raw:,}\n"
        f"  Total clean rows: {total_clean:,}\n"
        f"  Files processed:  {len(summaries)}"
    )
    return summaries


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Clean raw CICFlowMeter CSVs for SentinelNet V4."
    )
    p.add_argument(
        "--input", "-i",
        help="Path to a single input CSV (default: clean all in data/raw/)",
    )
    p.add_argument(
        "--output", "-o",
        default=_DEFAULT_CLEAN_DIR,
        help=f"Output directory (default: {_DEFAULT_CLEAN_DIR})",
    )
    p.add_argument(
        "--raw-dir",
        default=_DEFAULT_RAW_DIR,
        help=f"Directory of raw CSVs (default: {_DEFAULT_RAW_DIR})",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be done without writing any files.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.input:
        fname = os.path.splitext(os.path.basename(args.input))[0]
        out_path = os.path.join(args.output, fname + "_clean.csv")
        clean_single_file(args.input, out_path, dry_run=args.dry_run)
    else:
        clean_directory(
            raw_dir=args.raw_dir,
            clean_dir=args.output,
            dry_run=args.dry_run,
        )

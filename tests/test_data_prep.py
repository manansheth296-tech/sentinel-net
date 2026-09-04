"""
tests/test_data_prep.py — SentinelNet V4 Data Preprocessing Test Suite
=======================================================================

Tests every requirement from the task specification:
  - Raw CSV loading
  - Repeated header removal
  - NaN → 0
  - ±Inf → 0
  - Zero-duration flows (no crash)
  - Feature count == 77
  - State dimension == 156
  - Sequence shape == (20, 156)
  - Numerical validity post-preprocessing
  - Chronological / row-order preservation
  - Metadata columns excluded from model features
  - Scaler never fitted on test data

Run with:
    python -m pytest tests/test_data_prep.py -v
    # or from project root:
    python tests/test_data_prep.py
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import textwrap
import unittest

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Path setup — works whether run as `pytest tests/` or `python tests/test_data_prep.py`
# ---------------------------------------------------------------------------
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
for _p in [_PROJECT_ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.data_prep import (
    RAW_FEATURE_NAMES,
    FEATURE_COLS,
    SEQ_LEN,
    INPUT_DIM,
    WINDOW_ROWS,
    USING_REAL_TIME,
    load_raw_csv,
    normalise_columns,
    remove_repeated_headers,
    clean_numeric_features,
    detect_metadata_cols,
    assign_window_ids,
    aggregate_windows,
    reorder_to_v4,
    build_sequence,
    preprocess,
    load_scaler,
    _attach_is_attack,
)

_SCALER_PATH = os.path.join(_PROJECT_ROOT, "model", "scaler_v4.pkl")
_HAVE_SCALER = os.path.exists(_SCALER_PATH)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_valid_df(n_rows: int = 10, seed: int = 42) -> pd.DataFrame:
    """
    Build a minimal valid DataFrame with all 77 model features plus
    common metadata columns.
    """
    rng = np.random.default_rng(seed)
    data = {col: rng.random(n_rows).astype(np.float32) for col in RAW_FEATURE_NAMES}
    data["Label"] = ["Benign"] * n_rows
    data["Dst Port"] = rng.integers(1, 65535, n_rows).astype(str)
    data["Src IP"] = ["192.168.1.1"] * n_rows
    data["Dst IP"] = ["10.0.0.1"] * n_rows
    data["Flow ID"] = [f"flow_{i}" for i in range(n_rows)]
    data["Src Port"] = rng.integers(1024, 65535, n_rows).astype(str)
    return pd.DataFrame(data)


def _df_to_csv(df: pd.DataFrame) -> str:
    """Write df to a temp CSV file and return the path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False
    )
    df.to_csv(tmp.name, index=False)
    tmp.close()
    return tmp.name


def _make_enough_rows(extra: int = 0) -> pd.DataFrame:
    """Build a DataFrame large enough to produce >=20 windows."""
    n = SEQ_LEN * WINDOW_ROWS + extra
    return _make_valid_df(n_rows=n)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
class TestConstants(unittest.TestCase):
    """Verify the module loads the correct V4 constants."""

    def test_raw_feature_count(self):
        self.assertEqual(len(RAW_FEATURE_NAMES), 77,
                         "Expected exactly 77 raw model features.")

    def test_state_feature_count(self):
        self.assertEqual(len(FEATURE_COLS), 156,
                         "Expected exactly 156 state feature columns.")

    def test_seq_len(self):
        self.assertEqual(SEQ_LEN, 20, "Expected seq_len == 20.")

    def test_input_dim(self):
        self.assertEqual(INPUT_DIM, 156, "Expected input_dim == 156.")

    def test_feature_cols_ends_with_ports_count(self):
        self.assertEqual(FEATURE_COLS[-2], "unique_dst_ports")
        self.assertEqual(FEATURE_COLS[-1], "flow_count")

    def test_metadata_not_in_raw_features(self):
        banned = {"Label", "Timestamp", "Dst Port", "Flow ID",
                  "Src IP", "Dst IP", "Src Port"}
        overlap = set(RAW_FEATURE_NAMES) & banned
        self.assertEqual(overlap, set(),
                         f"Metadata columns leaked into RAW_FEATURE_NAMES: {overlap}")

    def test_metadata_not_in_feature_cols(self):
        banned = {"Label", "Timestamp", "Flow ID", "Src IP", "Dst IP", "Src Port"}
        # Dst Port is allowed in feature_cols as unique_dst_ports,
        # but not as a raw column
        overlap = set(FEATURE_COLS) & banned
        self.assertEqual(overlap, set(),
                         f"Metadata columns leaked into FEATURE_COLS: {overlap}")


class TestColumnNormalisation(unittest.TestCase):
    """Test alternate CICFlowMeter column name mapping."""

    def test_alt_names_mapped(self):
        df = pd.DataFrame(columns=[
            "Tot Fwd Pkts", "Tot Bwd Pkts",
            "Flow Byts/s", "Flow Pkts/s",
            "FIN Flag Cnt", "SYN Flag Cnt",
        ])
        result = normalise_columns(df)
        self.assertIn("Total Fwd Packets", result.columns)
        self.assertIn("Total Backward Packets", result.columns)
        self.assertIn("Flow Bytes/s", result.columns)
        self.assertIn("Flow Packets/s", result.columns)
        self.assertIn("FIN Flag Count", result.columns)
        self.assertIn("SYN Flag Count", result.columns)

    def test_already_canonical_unchanged(self):
        df = pd.DataFrame(columns=RAW_FEATURE_NAMES[:5])
        result = normalise_columns(df)
        for col in RAW_FEATURE_NAMES[:5]:
            self.assertIn(col, result.columns)


class TestRepeatedHeaderRemoval(unittest.TestCase):
    """Verify that repeated header rows are detected and removed."""

    def test_header_row_removed(self):
        df = _make_valid_df(n_rows=5)
        # Insert a duplicate header row at position 2
        header_row = pd.DataFrame(
            {col: [col] for col in df.columns}
        )
        df_with_header = pd.concat(
            [df.iloc[:2], header_row, df.iloc[2:]], ignore_index=True
        )
        cleaned = remove_repeated_headers(df_with_header)
        # Should be 5 data rows, not 6
        self.assertEqual(len(cleaned), 5)

    def test_no_header_rows_unchanged(self):
        df = _make_valid_df(n_rows=8)
        cleaned = remove_repeated_headers(df)
        self.assertEqual(len(cleaned), 8)

    def test_multiple_header_rows_all_removed(self):
        df = _make_valid_df(n_rows=4)
        header_row = pd.DataFrame({col: [col] for col in df.columns})
        combined = pd.concat(
            [header_row, df.iloc[:2], header_row, df.iloc[2:]], ignore_index=True
        )
        cleaned = remove_repeated_headers(combined)
        self.assertEqual(len(cleaned), 4)


class TestNaNHandling(unittest.TestCase):
    """NaN → 0 for every model feature; rows are kept, not dropped."""

    def test_nan_becomes_zero(self):
        df = _make_valid_df(n_rows=5)
        # Introduce NaN in several model-feature cells
        df.loc[0, RAW_FEATURE_NAMES[0]] = np.nan
        df.loc[2, RAW_FEATURE_NAMES[5]] = np.nan
        df.loc[4, RAW_FEATURE_NAMES[-1]] = np.nan

        cleaned = clean_numeric_features(df.copy())

        self.assertEqual(cleaned[RAW_FEATURE_NAMES].isna().sum().sum(), 0)
        self.assertEqual(cleaned.loc[0, RAW_FEATURE_NAMES[0]], 0.0)
        self.assertEqual(cleaned.loc[2, RAW_FEATURE_NAMES[5]], 0.0)
        self.assertEqual(cleaned.loc[4, RAW_FEATURE_NAMES[-1]], 0.0)

    def test_nan_rows_not_dropped(self):
        df = _make_valid_df(n_rows=5)
        # Make an entire row NaN for all model features
        for col in RAW_FEATURE_NAMES:
            df.loc[3, col] = np.nan
        cleaned = clean_numeric_features(df.copy())
        # Row 3 must still exist (all features → 0)
        self.assertEqual(len(cleaned), 5)


class TestInfHandling(unittest.TestCase):
    """+Inf → 0 and -Inf → 0; rows are kept."""

    def test_pos_inf_becomes_zero(self):
        df = _make_valid_df(n_rows=5)
        df.loc[1, RAW_FEATURE_NAMES[0]] = np.inf
        cleaned = clean_numeric_features(df.copy())
        self.assertEqual(cleaned.loc[1, RAW_FEATURE_NAMES[0]], 0.0)
        self.assertFalse(np.isinf(cleaned[RAW_FEATURE_NAMES].values).any())

    def test_neg_inf_becomes_zero(self):
        df = _make_valid_df(n_rows=5)
        df.loc[2, RAW_FEATURE_NAMES[3]] = -np.inf
        cleaned = clean_numeric_features(df.copy())
        self.assertEqual(cleaned.loc[2, RAW_FEATURE_NAMES[3]], 0.0)
        self.assertFalse(np.isinf(cleaned[RAW_FEATURE_NAMES].values).any())

    def test_inf_rows_not_dropped(self):
        df = _make_valid_df(n_rows=5)
        for col in RAW_FEATURE_NAMES:
            df.loc[0, col] = np.inf
        cleaned = clean_numeric_features(df.copy())
        self.assertEqual(len(cleaned), 5)

    def test_actual_zero_preserved(self):
        df = _make_valid_df(n_rows=5)
        df.loc[0, RAW_FEATURE_NAMES[0]] = 0.0
        cleaned = clean_numeric_features(df.copy())
        self.assertEqual(cleaned.loc[0, RAW_FEATURE_NAMES[0]], 0.0)


class TestZeroDuration(unittest.TestCase):
    """Zero-duration flows must not crash preprocessing."""

    def test_zero_flow_duration_survives(self):
        df = _make_valid_df(n_rows=5)
        df.loc[0, "Flow Duration"] = 0.0
        df.loc[1, "Flow Duration"] = 0.0
        # These columns may contain rate features derived from duration;
        # forcing them to a large value and then to 0 after Inf-cleaning
        if "Flow Bytes/s" in df.columns:
            df.loc[0, "Flow Bytes/s"] = np.inf
        try:
            cleaned = clean_numeric_features(df.copy())
            # If we reach here, no crash occurred
            self.assertEqual(len(cleaned), 5)
        except Exception as e:
            self.fail(f"Zero-duration flow raised an unexpected exception: {e}")


class TestWindowAssignment(unittest.TestCase):
    """Row-bucket windowing preserves order; does not shuffle."""

    def test_window_ids_monotone(self):
        df = _make_valid_df(n_rows=WINDOW_ROWS * 3)
        df = _attach_is_attack(df, None)
        df = assign_window_ids(df, timestamp_col=None, use_real_time=False)
        self.assertTrue((df["window_id"].diff().dropna() >= 0).all(),
                        "Window IDs are not monotonically non-decreasing.")

    def test_window_id_boundaries(self):
        df = _make_valid_df(n_rows=WINDOW_ROWS * 3)
        df = _attach_is_attack(df, None)
        df = assign_window_ids(df, timestamp_col=None, use_real_time=False)
        # Row 0 → window 0, row WINDOW_ROWS → window 1
        self.assertEqual(df.loc[0, "window_id"], 0)
        self.assertEqual(df.loc[WINDOW_ROWS, "window_id"], 1)
        self.assertEqual(df.loc[WINDOW_ROWS * 2, "window_id"], 2)

    def test_chronological_order_preserved(self):
        """
        Rows must emerge in their original (file-order / chronological) sequence.
        """
        df = _make_valid_df(n_rows=WINDOW_ROWS * 2)
        # Tag rows with their original index
        df["_orig_idx"] = np.arange(len(df))
        df = _attach_is_attack(df, None)
        df = assign_window_ids(df, timestamp_col=None, use_real_time=False)
        # Within each window, original order must be preserved
        for wid, group in df.groupby("window_id"):
            orig = group["_orig_idx"].values
            self.assertTrue(
                (np.diff(orig) > 0).all(),
                f"Window {wid}: rows are not in original order.",
            )


class TestStateVectorShape(unittest.TestCase):
    """Aggregate → 156-D state vectors."""

    def test_state_dim_156(self):
        df = _make_valid_df(n_rows=WINDOW_ROWS * 5)
        df = _attach_is_attack(df, None)
        df = assign_window_ids(df, timestamp_col=None, use_real_time=False)
        state_df = aggregate_windows(df)
        state_156 = reorder_to_v4(state_df)
        self.assertEqual(state_156.shape[1], 156)

    def test_state_has_no_nan(self):
        df = _make_valid_df(n_rows=WINDOW_ROWS * 5)
        # Inject NaN before aggregation — should still produce 0.0 in state
        df.loc[0, RAW_FEATURE_NAMES[0]] = np.nan
        df = _attach_is_attack(df, None)
        df = assign_window_ids(df, timestamp_col=None, use_real_time=False)
        state_df = aggregate_windows(df)
        state_156 = reorder_to_v4(state_df)
        self.assertEqual(state_156[FEATURE_COLS].isna().sum().sum(), 0)

    def test_state_layout_interleaved_mean_std(self):
        """
        Verify that FEATURE_COLS uses the V4 interleaved layout:
          [2i]   = <raw_feature[i]>_mean
          [2i+1] = <raw_feature[i]>_std
        for i in 0..76, followed by unique_dst_ports and flow_count at [154],[155].

        This differs from a "77 means then 77 stds" layout — the V4 export
        bundle interleaves mean/std per feature.
        """
        for i, raw in enumerate(RAW_FEATURE_NAMES):
            self.assertEqual(
                FEATURE_COLS[2 * i], f"{raw}_mean",
                f"Position {2*i}: expected '{raw}_mean', got '{FEATURE_COLS[2*i]}'",
            )
            self.assertEqual(
                FEATURE_COLS[2 * i + 1], f"{raw}_std",
                f"Position {2*i+1}: expected '{raw}_std', got '{FEATURE_COLS[2*i+1]}'",
            )
        self.assertEqual(FEATURE_COLS[154], "unique_dst_ports")
        self.assertEqual(FEATURE_COLS[155], "flow_count")


class TestSequenceShape(unittest.TestCase):
    """build_sequence → (20, 156)."""

    def test_sequence_shape(self):
        n_windows = SEQ_LEN + 5
        fake_scaled = np.random.rand(n_windows, 156).astype(np.float32)
        seq = build_sequence(fake_scaled, seq_len=SEQ_LEN)
        self.assertEqual(seq.shape, (SEQ_LEN, 156))

    def test_sequence_is_last_n_windows(self):
        n_windows = SEQ_LEN + 5
        fake_scaled = np.arange(n_windows * 156, dtype=np.float32).reshape(n_windows, 156)
        seq = build_sequence(fake_scaled, seq_len=SEQ_LEN)
        np.testing.assert_array_equal(seq, fake_scaled[-SEQ_LEN:])

    def test_sequence_too_few_windows_raises(self):
        fake_scaled = np.random.rand(SEQ_LEN - 1, 156).astype(np.float32)
        with self.assertRaises(ValueError):
            build_sequence(fake_scaled, seq_len=SEQ_LEN)


class TestNumericalValidity(unittest.TestCase):
    """After a full preprocessing pass, the output must be free of NaN/Inf."""

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_sequence_no_nan_no_inf(self):
        df = _make_enough_rows()
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            seq = result["sequence"]
            self.assertFalse(np.isnan(seq).any(), "NaN found in output sequence.")
            self.assertFalse(np.isinf(seq).any(), "Inf found in output sequence.")
        finally:
            os.unlink(csv_path)


class TestEndToEnd(unittest.TestCase):
    """Full preprocess() run — requires scaler_v4.pkl in model/."""

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_sequence_shape_end_to_end(self):
        df = _make_enough_rows()
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            seq = result["sequence"]
            self.assertEqual(
                seq.shape, (SEQ_LEN, INPUT_DIM),
                f"Expected ({SEQ_LEN}, {INPUT_DIM}), got {seq.shape}.",
            )
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_raw_feature_count_in_schema(self):
        df = _make_enough_rows()
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            self.assertEqual(result["schema"]["raw_feature_count"], 77)
            self.assertEqual(result["schema"]["state_feature_count"], 156)
            self.assertEqual(result["schema"]["seq_len"], SEQ_LEN)
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_repeated_header_in_csv(self):
        df = _make_enough_rows()
        # Insert two repeated header rows in the middle
        header_row = pd.DataFrame({col: [col] for col in df.columns})
        combined = pd.concat(
            [df.iloc[:100], header_row, df.iloc[100:500], header_row, df.iloc[500:]],
            ignore_index=True,
        )
        csv_path = _df_to_csv(combined)
        try:
            scaler = load_scaler()
            # Should not raise
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            self.assertEqual(result["sequence"].shape, (SEQ_LEN, INPUT_DIM))
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_nan_in_csv_survives(self):
        df = _make_enough_rows()
        df.loc[0, RAW_FEATURE_NAMES[0]] = np.nan
        df.loc[100, RAW_FEATURE_NAMES[5]] = np.nan
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            self.assertEqual(result["sequence"].shape, (SEQ_LEN, INPUT_DIM))
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_inf_in_csv_survives(self):
        df = _make_enough_rows()
        df.loc[0, "Flow Bytes/s"] = np.inf
        df.loc[1, "Flow Packets/s"] = -np.inf
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            self.assertEqual(result["sequence"].shape, (SEQ_LEN, INPUT_DIM))
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_zero_duration_flows(self):
        df = _make_enough_rows()
        df.loc[0:10, "Flow Duration"] = 0.0
        df.loc[0:10, "Flow Bytes/s"] = np.inf   # typical result of 0-duration
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            self.assertEqual(result["sequence"].shape, (SEQ_LEN, INPUT_DIM))
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_metadata_not_in_sequence(self):
        """
        Flow ID, Src IP, Dst IP, Label must not enter the 156-D state vector.
        """
        df = _make_enough_rows()
        csv_path = _df_to_csv(df)
        try:
            scaler = load_scaler()
            result = preprocess(csv_path, scaler=scaler, use_real_time=False)
            # The sequence is a plain float32 array — no way for string metadata
            # to survive.  We also verify the state_df schema.
            state_df = result["state_df"]
            for banned in ("Label", "Flow ID", "Src IP", "Dst IP", "Src Port"):
                self.assertNotIn(
                    banned, state_df.columns,
                    f"Metadata column '{banned}' leaked into state_df.",
                )
        finally:
            os.unlink(csv_path)

    @unittest.skipUnless(_HAVE_SCALER, "scaler_v4.pkl not found — skipping end-to-end test.")
    def test_scaler_not_refitted(self):
        """
        Verify the scaler's mean_ and scale_ are unchanged after preprocess().
        This confirms we only call .transform(), never .fit_transform().
        """
        scaler = load_scaler()
        mean_before = scaler.mean_.copy()
        scale_before = scaler.scale_.copy()

        df = _make_enough_rows()
        csv_path = _df_to_csv(df)
        try:
            preprocess(csv_path, scaler=scaler, use_real_time=False)
        finally:
            os.unlink(csv_path)

        np.testing.assert_array_equal(
            scaler.mean_, mean_before,
            err_msg="Scaler mean_ changed — scaler was re-fitted during preprocess().",
        )
        np.testing.assert_array_equal(
            scaler.scale_, scale_before,
            err_msg="Scaler scale_ changed — scaler was re-fitted during preprocess().",
        )


class TestBaselineLeakage(unittest.TestCase):
    """
    Verify that the standard NON_FEATURE_COLS from train_baseline.py
    are all excluded from RAW_FEATURE_NAMES and FEATURE_COLS.
    """

    BASELINE_EXCLUDED = {
        "Label", "Timestamp", "Dst Port", "Flow ID", "Src IP", "Dst IP", "Src Port"
    }

    def test_excluded_not_in_raw_features(self):
        overlap = set(RAW_FEATURE_NAMES) & self.BASELINE_EXCLUDED
        self.assertEqual(
            overlap, set(),
            f"Baseline-excluded columns found in RAW_FEATURE_NAMES: {overlap}",
        )

    def test_excluded_not_in_feature_cols(self):
        overlap = set(FEATURE_COLS) & self.BASELINE_EXCLUDED
        self.assertEqual(
            overlap, set(),
            f"Baseline-excluded columns found in FEATURE_COLS: {overlap}",
        )


# ---------------------------------------------------------------------------
# Allow `python tests/test_data_prep.py` as well as `pytest`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main(verbosity=2)

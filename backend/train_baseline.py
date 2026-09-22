import argparse
import gc
import glob
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Column / cache constants
# ---------------------------------------------------------------------------
NON_FEATURE_COLS = {
    'Label', 'Timestamp', 'Dst Port', 'Flow ID',
    'Src IP', 'Dst IP', 'Src Port', '_source_file',
}

_CACHE_SUBDIR        = '.cache'          # subdirectory inside real_data_dir
_MIN_ROWS_HARD_FAIL  = 100_000           # hard-fail if a file has fewer rows
_NAN_WARN_THRESHOLD  = 0.05             # warn if >5% of rows have bad strings
_BAD_STRINGS         = frozenset({
    'nan', 'NaN', 'NAN', 'Infinity', 'infinity', 'Inf', 'inf', '-Infinity',
})

# ---------------------------------------------------------------------------
# Parquet availability
# ---------------------------------------------------------------------------
try:
    import pyarrow  # noqa: F401
    _PARQUET_AVAILABLE = True
except ImportError:
    _PARQUET_AVAILABLE = False

# In-memory cache used as fallback when pyarrow is not installed.
# Keyed by csv basename (e.g. 'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv').
_FRAME_CACHE: dict = {}


# ---------------------------------------------------------------------------
# Raw-CSV loaders  (used for the small bundled sample_ files only)
# ---------------------------------------------------------------------------

def _load_single_file(path: str, sample_frac: float = 1.0) -> pd.DataFrame:
    """
    Read one CIC-IDS-2018-style CSV, strip column names, drop stray header
    rows (Label == 'Label' — a known CICFlowMeter artifact), optionally
    subsample, and tag every row with its source filename so leave-*-out
    splits stay file-level clean.
    """
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    if 'Label' in df.columns:
        df = df[df['Label'] != 'Label'].copy()
    if 0.0 < sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
    df['_source_file'] = os.path.basename(path)
    return df


def _discover_sample_files(data_dir: str) -> list:
    """Return up to 3 sorted sample_ CSV files (falling back to all CSVs)."""
    all_csv = glob.glob(os.path.join(data_dir, '*.csv'))
    sample_files = sorted(f for f in all_csv
                          if os.path.basename(f).startswith('sample_'))
    return (sample_files if sample_files else sorted(all_csv))[:3]


def _discover_real_day_files(real_data_dir: str) -> list:
    """Return all CSV files in real_data_dir, sorted alphabetically."""
    return sorted(glob.glob(os.path.join(real_data_dir, '*.csv')))


def _df_to_Xy(df: pd.DataFrame):
    """Convert a raw/uncached DataFrame to (X, y, feature_cols)."""
    label_col    = 'Label'
    y            = (df[label_col] != 'Benign').astype(int)
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = (df[feature_cols]
         .apply(pd.to_numeric, errors='coerce')
         .replace([np.inf, -np.inf], np.nan)
         .fillna(0))
    return X, y, feature_cols


def _df_to_Xy_cached(df: pd.DataFrame):
    """
    Like _df_to_Xy but for pre-cleaned cached DataFrames.
    Numeric cols are already float32 with no NaN/Inf — skips the expensive
    coerce / fillna pipeline, halving peak memory for large test sets.
    """
    label_col    = 'Label'
    y            = (df[label_col] != 'Benign').astype(int)
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X            = df[feature_cols]   # already float32, no NaN/Inf
    return X, y, feature_cols


def load_and_preprocess_clean(data_dir: str, sample_frac: float = 0.05):
    """
    Public interface (unchanged signature). Loads up to 3 sample_ CSVs,
    subsamples each at sample_frac, concatenates, and returns (X, y,
    feature_cols).

    File selection: prefers files starting with 'sample_' (the labeled
    attack-vs-benign CSVs bundled with this repo). Falls back to all CSVs
    in data_dir if no sample_ files are present.
    Non-feature / leaky identifier columns are excluded: Label, Timestamp,
    Dst Port, Flow ID, Src IP, Dst IP, Src Port.
    """
    csv_files = _discover_sample_files(data_dir)
    frames    = [_load_single_file(f, sample_frac) for f in csv_files]
    df        = pd.concat(frames, ignore_index=True)
    return _df_to_Xy(df)


# ---------------------------------------------------------------------------
# Parquet cache — combined single-pass clean + validate + write
# ---------------------------------------------------------------------------

def _cache_file_paths(source_path: str, cache_dir: str):
    """Return (parquet_path, stats_json_path) for a given source CSV."""
    stem = os.path.basename(source_path).rsplit('.', 1)[0]
    return (
        os.path.join(cache_dir, stem + '.parquet'),
        os.path.join(cache_dir, stem + '_stats.json'),
    )


def _build_file_cache(path: str, cache_dir: str,
                      ref_cols: set = None) -> tuple:
    """
    Combined single-pass cache builder for one real-day CSV.

    Reads the source CSV EXACTLY ONCE in 100K-row chunks, simultaneously:
      1. Header check (nrows=0 — instant, before the chunked loop).
      2. Stray-header-row counting and removal (Label == 'Label').
      3. NaN/Infinity string scan on numeric cols BEFORE pd.to_numeric coerce
         (so the count reflects genuine bad-string cells, not just post-coerce NaN).
      4. Numeric inf/NaN counting AFTER coerce.
      5. inf->nan->0 fill + cast to float32 (halves memory vs float64).
      6. Retains only feature cols + Label + _source_file tag
         (drops Timestamp, Flow ID, Src/Dst IP — never used in modelling).

    Writes two sidecar files to cache_dir:
      *.parquet  — cleaned DataFrame (fast to re-read on subsequent runs)
      *_stats.json — validation stats (row counts, label dist, NaN/Inf counts)

    Cache is valid as long as both sidecar files exist AND are newer than the
    source CSV. On a cache hit, stats are loaded from JSON and no CSV parsing
    is done.

    Returns (parquet_path_or_None, stats_dict).
    """
    fn           = os.path.basename(path)
    parquet_path, stats_path = _cache_file_paths(path, cache_dir)

    # --- Cache hit? Load stats from sidecar, skip CSV parse entirely ---
    if os.path.exists(parquet_path) and os.path.exists(stats_path):
        src_mtime   = os.path.getmtime(path)
        cache_mtime = min(os.path.getmtime(parquet_path),
                          os.path.getmtime(stats_path))
        if cache_mtime > src_mtime:
            with open(stats_path) as fh:
                stats = json.load(fh)
            print(f'    cache hit -> {os.path.basename(parquet_path)}', flush=True)
            return parquet_path, stats

    # --- Cache miss: single combined CSV parse ---
    print(f'    cache miss — single combined parse/validation pass …', flush=True)
    os.makedirs(cache_dir, exist_ok=True)

    # Pass 1 (instant): column header check
    df_head = pd.read_csv(path, nrows=0, low_memory=False)
    df_head.columns = df_head.columns.str.strip()
    cols = list(df_head.columns)
    col_mismatches: dict = {}
    if ref_cols is not None:
        extra   = sorted(set(cols) - ref_cols)
        missing = sorted(ref_cols - set(cols))
        if extra or missing:
            col_mismatches = {'extra': extra, 'missing': missing}

    feat_cols = [c for c in cols if c not in NON_FEATURE_COLS]

    # Validation counters
    stray_rows    = 0
    total_rows    = 0
    label_counts: dict = {}
    nan_str_rows  = 0
    inf_num_cells = 0
    nan_num_cells = 0
    cleaned_chunks: list = []

    for chunk in pd.read_csv(path, chunksize=100_000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()

        # Remove stray header-as-data rows
        stray_mask  = chunk['Label'] == 'Label'
        stray_rows += int(stray_mask.sum())
        chunk       = chunk[~stray_mask]
        if len(chunk) == 0:
            continue

        total_rows += len(chunk)
        for lbl, cnt in chunk['Label'].value_counts().items():
            label_counts[str(lbl)] = label_counts.get(str(lbl), 0) + int(cnt)

        # NaN/Inf STRING scan BEFORE numeric coerce
        str_view      = chunk[feat_cols].astype(str)
        nan_str_rows += int(str_view.isin(_BAD_STRINGS).any(axis=1).sum())
        del str_view

        # Numeric coerce -> count inf/nan cells
        num_coerced    = chunk[feat_cols].apply(pd.to_numeric, errors='coerce')
        inf_num_cells += int(np.isinf(num_coerced.values).sum())
        nan_num_cells += int(np.isnan(num_coerced.values).sum())

        # Finalize chunk: clean + cast to float32
        num_clean = (num_coerced
                     .replace([np.inf, -np.inf], np.nan)
                     .fillna(0)
                     .astype(np.float32))
        del num_coerced

        # Reassemble: Label + cleaned numeric cols + source tag
        out = pd.concat([
            chunk[['Label']].reset_index(drop=True),
            num_clean.reset_index(drop=True),
        ], axis=1)
        out['_source_file'] = fn
        cleaned_chunks.append(out)
        del chunk, num_clean; gc.collect()

    if not cleaned_chunks:
        raise ValueError(f'{fn}: no data rows survived cleaning.')

    df_clean = pd.concat(cleaned_chunks, ignore_index=True)
    del cleaned_chunks; gc.collect()

    nan_pct = round(100.0 * nan_str_rows / total_rows, 4) if total_rows > 0 else 0.0

    # Write parquet cache (preferred) or keep in-memory dict (fallback)
    if _PARQUET_AVAILABLE:
        df_clean.to_parquet(parquet_path, index=False, compression='snappy')
        del df_clean; gc.collect()
    else:
        # No pyarrow: store the cleaned DataFrame in the module-level in-memory
        # cache so that _load_cached() can serve subsequent fold reads without
        # re-parsing the raw CSV.  Memory cost: ~300 MB per file (float32).
        _FRAME_CACHE[fn] = df_clean   # keep alive — do NOT gc here
        parquet_path = None

    stats = {
        'file':                           fn,
        'total_rows':                     total_rows,
        'stray_header_rows':              stray_rows,
        'label_counts':                   label_counts,
        'column_mismatches':              col_mismatches,
        'rows_with_bad_string_values':    nan_str_rows,
        'inf_numeric_cells':              inf_num_cells,
        'nan_numeric_cells_after_coerce': nan_num_cells,
        'nan_pct':                        nan_pct,
    }
    if parquet_path:
        with open(stats_path, 'w') as fh:
            json.dump(stats, fh, indent=2)

    return parquet_path, stats


def _load_cached(path: str, sample_frac: float = 1.0) -> pd.DataFrame:
    """
    Load a pre-cleaned DataFrame from the appropriate cache:
      1. Module-level _FRAME_CACHE (used when pyarrow is not installed).
      2. Parquet file on disk (normal path when pyarrow is available).

    path is the value stored in cache_paths by validate_real_data_files —
    either a *.parquet path (when pyarrow available) or the raw *.csv path
    (when not, in which case _FRAME_CACHE[basename] was populated during
    _build_file_cache).  Either way, reading from cache means the raw CSV
    is never re-parsed for fold reads.
    """
    fn = os.path.basename(path)
    if fn in _FRAME_CACHE:
        # In-memory cache hit (pyarrow-less fallback)
        df = _FRAME_CACHE[fn]
    elif path.endswith('.parquet'):
        df = pd.read_parquet(path)
    else:
        raise RuntimeError(
            f'_load_cached: no cache entry for {fn} and path is not a parquet file. '
            'This should not happen — _build_file_cache must be called first.'
        )
    if 0.0 < sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
    return df


# ---------------------------------------------------------------------------
# Validation  (wraps _build_file_cache for all files + reporting)
# ---------------------------------------------------------------------------

def validate_real_data_files(real_data_dir: str,
                              ref_cols: set = None,
                              hard_fail: bool = True):
    """
    Validate + cache all CSV files in real_data_dir.

    Calls _build_file_cache() for each file — which performs a SINGLE
    combined clean/validate/write-parquet pass per file (or skips parsing
    entirely on cache hits). This replaces the previous multi-pass approach
    (separate header sniff, label-only read, and chunked NaN scan).

    Hard failures (abort training unless hard_fail=False):
      - Any file has < _MIN_ROWS_HARD_FAIL rows  ->  likely truncated download.
      - Column sets differ between files  ->  incompatible schemas.
      - Any file's column set differs from ref_cols (sample files).

    Soft warnings (logged, training continues):
      - Stray header rows (auto-dropped during cache build).
      - NaN/Inf string rate > _NAN_WARN_THRESHOLD.

    Returns (report_dict, cache_paths_dict):
      report_dict:      for inclusion in --output-json
      cache_paths_dict: {csv_basename: parquet_path} for run_leave_day_out
    """
    files = _discover_real_day_files(real_data_dir)
    if not files:
        raise SystemExit(f'No CSV files found in --real-data-dir: {real_data_dir}')

    cache_dir = os.path.join(real_data_dir, _CACHE_SUBDIR)
    all_cached = (
        _PARQUET_AVAILABLE and
        all(os.path.exists(_cache_file_paths(p, cache_dir)[0]) for p in files) and
        all(os.path.exists(_cache_file_paths(p, cache_dir)[1]) for p in files) and
        all(min(os.path.getmtime(_cache_file_paths(p, cache_dir)[0]),
                os.path.getmtime(_cache_file_paths(p, cache_dir)[1]))
            > os.path.getmtime(p) for p in files)
    )
    mode = 'cache hit (loading stats from sidecar JSON)' if all_cached \
           else 'cache miss (single combined parse + validation pass)'
    print(f'\nValidation: {mode}', flush=True)
    print('=' * 72)

    report: dict = {
        'passed': True, 'warnings': [], 'hard_failures': [], 'files': [],
    }
    cache_paths: dict = {}
    first_col_set: set = None

    for path in files:
        fn = os.path.basename(path)
        print(f'  [{fn}]', flush=True)
        parquet_path, stats = _build_file_cache(path, cache_dir, ref_cols)
        report['files'].append(stats)
        cache_paths[fn] = parquet_path if parquet_path else path

        # Print per-file summary
        attack_rows = sum(v for k, v in stats['label_counts'].items()
                          if k != 'Benign')
        atk_pct = 100.0 * attack_rows / stats['total_rows'] if stats['total_rows'] else 0
        print(f'    rows={stats["total_rows"]:>12,}  '
              f'stray_header_rows={stats["stray_header_rows"]}')
        print(f'    attack_rows={attack_rows:,} ({atk_pct:.2f}%)  '
              f'labels={list(stats["label_counts"].keys())}')
        print(f'    bad_string_rows={stats["rows_with_bad_string_values"]:,} '
              f'({stats["nan_pct"]:.3f}%)  '
              f'inf_numeric_cells={stats["inf_numeric_cells"]:,}')
        if stats['column_mismatches']:
            print(f'    *** COLUMN MISMATCH: {stats["column_mismatches"]} ***')

        # Cross-file column consistency (fast: read header only)
        file_col_set = set(
            pd.read_csv(path, nrows=0, low_memory=False).columns.str.strip()
        )
        if first_col_set is None:
            first_col_set = file_col_set
        else:
            diff_extra   = sorted(file_col_set - first_col_set)
            diff_missing = sorted(first_col_set - file_col_set)
            if diff_extra or diff_missing:
                msg = (f'{fn}: column set differs from first file — '
                       f'extra={diff_extra}, missing={diff_missing}')
                report['hard_failures'].append(msg)
                report['passed'] = False
                print(f'    *** HARD FAIL: {msg}')

        # Hard fail: too few rows
        if stats['total_rows'] < _MIN_ROWS_HARD_FAIL:
            msg = (f'{fn}: only {stats["total_rows"]:,} rows '
                   f'(< {_MIN_ROWS_HARD_FAIL:,} minimum). '
                   'Likely a truncated or corrupted download.')
            report['hard_failures'].append(msg)
            report['passed'] = False
            print(f'    *** HARD FAIL: {msg}')

        if stats['column_mismatches']:
            msg = f'{fn}: column mismatch vs sample files — {stats["column_mismatches"]}'
            report['hard_failures'].append(msg)
            report['passed'] = False

        # Soft warnings
        if stats['stray_header_rows'] > 0:
            w = (f'{fn}: {stats["stray_header_rows"]} stray header row(s) — '
                 'dropped automatically during cache build.')
            report['warnings'].append(w)
            print(f'    WARNING: {w}')

        if stats['nan_pct'] > _NAN_WARN_THRESHOLD * 100:
            w = (f'{fn}: {stats["rows_with_bad_string_values"]:,} rows '
                 f'({stats["nan_pct"]:.1f}%) have NaN/Infinity string values — '
                 'zero-filled during cache build.')
            report['warnings'].append(w)
            print(f'    WARNING: {w}')
        print()

    print('=' * 72)
    if report['warnings']:
        print(f'  {len(report["warnings"])} warning(s) — see above.')
    if report['hard_failures']:
        print(f'  {len(report["hard_failures"])} HARD FAILURE(S):')
        for hf in report['hard_failures']:
            print(f'    *** {hf}')
    if report['passed']:
        print('  Validation PASSED — proceeding to leave-day-out training.')
    else:
        if hard_fail:
            raise SystemExit(
                f'\nValidation FAILED with {len(report["hard_failures"])} '
                'hard failure(s). Fix the issues above before running '
                'leave-day-out. Pass --skip-validation to bypass (not recommended).'
            )
        else:
            print('  Validation FAILED — proceeding anyway (--skip-validation active).')
    print()
    return report, cache_paths


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def _compute_metrics(y_true, y_pred, y_score=None) -> dict:
    """
    Return a comprehensive metrics dict.

    Always included:
      f1, precision, recall, fpr
      tp, fp, fn, tn          (raw confusion-matrix counts)
      positives_in_test        (= tp + fn)
      positives_in_test_pct   (% of test set that is the positive class)
      test_size

    Included when y_score (predicted probabilities) is provided AND both
    classes are present in y_true:
      average_precision  (PR-AUC — independent of the 0.5 decision threshold;
                          far more informative than F1 when positives are rare,
                          e.g. the Thursday-22-02 fold with 0.035% attack rate)

    When only one class is present in y_true (degenerate test set),
    average_precision is set to None and a note is included.
    """
    # Always force a 2×2 confusion matrix regardless of class presence in y_true
    cm          = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    f1   = float(f1_score(y_true, y_pred, zero_division=0))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec  = float(recall_score(y_true, y_pred, zero_division=0))
    fpr  = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    test_size       = int(len(y_true))
    pos_in_test     = tp + fn
    pos_pct         = round(100.0 * pos_in_test / test_size, 4) if test_size > 0 else 0.0

    n_classes = len(np.unique(y_true))
    avg_prec  = None
    if y_score is not None and n_classes > 1:
        try:
            avg_prec = float(average_precision_score(y_true, y_score))
        except Exception:
            avg_prec = None

    return {
        'f1':                    f1,
        'precision':             prec,
        'recall':                rec,
        'fpr':                   fpr,
        'tp':                    tp,
        'fp':                    fp,
        'fn':                    fn,
        'tn':                    tn,
        'average_precision':     avg_prec,
        'positives_in_test':     pos_in_test,
        'positives_in_test_pct': pos_pct,
        'test_size':             test_size,
    }


def _train_and_eval(X_train, y_train, X_test, y_test) -> dict:
    """Fit StandardScaler + LogisticRegression; return full metric dict."""
    scaler  = StandardScaler()
    X_tr_s  = scaler.fit_transform(X_train)
    X_te_s  = scaler.transform(X_test)
    clf     = LogisticRegression(max_iter=1000, random_state=42)
    clf.fit(X_tr_s, y_train)
    y_pred  = clf.predict(X_te_s)
    y_score = clf.predict_proba(X_te_s)[:, 1]   # positive-class probabilities
    return _compute_metrics(y_test, y_pred, y_score)


# ---------------------------------------------------------------------------
# Split modes
# ---------------------------------------------------------------------------

def run_stratified(data_dir: str, sample_frac: float) -> dict:
    """
    Stratified random 80/20 split on combined sampled data (bundled sample files).

    NOTE: rows from ALL files appear in both train and test splits —
    stratification is by class label, not by source file. This enables
    file-identity shortcuts. Use leave-file-out / leave-day-out to diagnose.
    """
    X, y, feature_cols = load_and_preprocess_clean(data_dir, sample_frac)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    metrics = _train_and_eval(X_train, y_train, X_test, y_test)
    metrics['train_size'] = int(len(X_train))
    return metrics


def run_leave_file_out(data_dir: str, sample_frac: float) -> list:
    """
    Leave-one-file-out cross-validation on the bundled sample_ CSVs.

    For each fold:
      - Train on the OTHER N-1 files (subsampled at sample_frac each).
      - Test on the HELD-OUT file IN FULL (no subsampling).

    These are small files (~1.4 MB each); no parquet caching needed.
    The full metric set (including TP/FP/FN/TN and average_precision)
    is returned for every fold.
    """
    csv_files = _discover_sample_files(data_dir)
    if len(csv_files) < 2:
        raise ValueError(
            f'Need at least 2 sample_ CSVs for leave-file-out; '
            f'found {len(csv_files)} in {data_dir}'
        )
    results = []
    for held_idx, held_path in enumerate(csv_files):
        held_name    = os.path.basename(held_path)
        train_paths  = [f for i, f in enumerate(csv_files) if i != held_idx]
        train_frames = [_load_single_file(p, sample_frac) for p in train_paths]
        df_train     = pd.concat(train_frames, ignore_index=True)
        X_train, y_train, _ = _df_to_Xy(df_train)
        df_test = _load_single_file(held_path, sample_frac=1.0)
        X_test, y_test, _  = _df_to_Xy(df_test)
        metrics = _train_and_eval(X_train, y_train, X_test, y_test)
        metrics['held_out']    = held_name
        metrics['train_files'] = [os.path.basename(p) for p in train_paths]
        results.append(metrics)
        del train_frames, df_train, df_test, X_train, y_train, X_test, y_test
        gc.collect()
    return results


def run_leave_day_out(real_data_dir: str,
                      sample_frac: float,
                      cache_paths: dict) -> list:
    """
    Leave-one-day-out cross-validation on the real CSE-CIC-IDS2018 day files.

    CACHING: each source CSV is parsed at most ONCE across the entire run
    (during _build_file_cache in validate_real_data_files). Every fold reads
    from the pre-cleaned parquet cache, never from the raw CSV again.

    For each fold:
      - Train on the OTHER N-1 day files (read from parquet, subsampled at
        sample_frac in memory — fast, no additional I/O per fold).
      - Test on the HELD-OUT day file IN FULL (read from parquet at 100%).

    Returns a list of fold dicts with the full metric set including
    tp/fp/fn/tn, average_precision, positives_in_test_pct.

    Key data note — Thursday-22-02 fold (0.035% attack rate in test set):
      F1 will be very low purely due to base-rate arithmetic (22K+ FPs from
      2.2% FPR swamp ~129 TPs from a pool of 362 attack rows). This is NOT
      a leakage indicator. Interpret via average_precision and tp counts, not F1.
    """
    csv_files = _discover_real_day_files(real_data_dir)
    if len(csv_files) < 2:
        raise ValueError(
            f'Need at least 2 day CSV files for leave-day-out; '
            f'found {len(csv_files)} in {real_data_dir}'
        )

    results = []
    n_folds = len(csv_files)

    for held_idx, held_path in enumerate(csv_files):
        held_name   = os.path.basename(held_path)
        train_paths = [f for i, f in enumerate(csv_files) if i != held_idx]

        print(f'\n  [Fold {held_idx + 1}/{n_folds}] held-out = {held_name}',
              flush=True)
        print(f'             training on '
              f'{[os.path.basename(p) for p in train_paths]}', flush=True)

        # Training: read from parquet cache (fast), subsample in memory
        print(f'             Loading training files from cache '
              f'at {sample_frac * 100:.1f}% …', flush=True)
        train_frames = [
            _load_cached(cache_paths[os.path.basename(p)], sample_frac)
            for p in train_paths
        ]
        df_train = pd.concat(train_frames, ignore_index=True)
        del train_frames; gc.collect()

        X_train, y_train, _ = _df_to_Xy_cached(df_train)
        del df_train; gc.collect()
        print(f'             train_size={len(X_train):,}  '
              f'attack_rows={int(y_train.sum()):,}  '
              f'benign_rows={int((y_train == 0).sum()):,}', flush=True)

        # Test: full file from parquet cache
        print(f'             Loading test file from cache (full) …', flush=True)
        df_test = _load_cached(cache_paths[held_name], sample_frac=1.0)
        X_test, y_test, _ = _df_to_Xy_cached(df_test)
        del df_test; gc.collect()
        pos = int(y_test.sum())
        print(f'             test_size={len(X_test):,}  '
              f'attack_rows={pos:,} ({100 * pos / len(X_test):.3f}%)  '
              f'benign_rows={int((y_test == 0).sum()):,}', flush=True)

        print('             Training LogisticRegression …', flush=True)
        metrics = _train_and_eval(X_train, y_train, X_test, y_test)
        del X_train, y_train, X_test, y_test; gc.collect()

        metrics['held_out']    = held_name
        metrics['train_files'] = [os.path.basename(p) for p in train_paths]
        results.append(metrics)

        avg_p_str = (f'{metrics["average_precision"]:.4f}'
                     if metrics['average_precision'] is not None else 'N/A')
        print(f'             F1={metrics["f1"]:.4f}  '
              f'Prec={metrics["precision"]:.4f}  '
              f'Rec={metrics["recall"]:.4f}  '
              f'FPR={metrics["fpr"]:.4f}  '
              f'AvgPrec={avg_p_str}  '
              f'TP={metrics["tp"]:,}  FP={metrics["fp"]:,}  '
              f'FN={metrics["fn"]:,}  TN={metrics["tn"]:,}', flush=True)

    return results


# ---------------------------------------------------------------------------
# Console output helpers
# ---------------------------------------------------------------------------

def _print_metrics_block(label: str, m: dict):
    pad = max(len(label) + 4, 52)
    print('=' * pad)
    print(f'  {label}')
    print('=' * pad)
    print(f'  F1 Score:          {m["f1"]:.4f}')
    print(f'  Precision:         {m["precision"]:.4f}')
    print(f'  Recall:            {m["recall"]:.4f}')
    print(f'  FPR:               {m["fpr"]:.4f}')
    avg_p = m.get('average_precision')
    if avg_p is not None:
        print(f'  Average Precision: {avg_p:.4f}')
    if 'tp' in m:
        print(f'  TP={m["tp"]:,}  FP={m["fp"]:,}  '
              f'FN={m["fn"]:,}  TN={m["tn"]:,}')
    if 'positives_in_test' in m:
        print(f'  Positives in test: {m["positives_in_test"]:,} / '
              f'{m["test_size"]:,} ({m.get("positives_in_test_pct", 0):.3f}%)')
    print('=' * pad)


def _print_fold_table(results: list, title: str):
    """Print a formatted fold-result table with F1-variance and imbalance flags."""
    print()
    print('=' * 84)
    print(f'  {title}')
    print('=' * 84)
    print(f'  {"Held-out file":<44} {"F1":>6}  {"AvgP":>6}  '
          f'{"Rec":>6}  {"FPR":>6}  {"TP":>9}')
    print(f'  {"-"*44} {"------":>6}  {"------":>6}  '
          f'{"------":>6}  {"------":>6}  {"---------":>9}')
    for r in results:
        name  = r['held_out']
        avg_p = r.get('average_precision')
        avg_p_str = f'{avg_p:.4f}' if avg_p is not None else '  N/A '
        pct   = r.get('positives_in_test_pct', 0)
        flag  = ' [<1% attack]' if pct < 1.0 else ''
        print(f'  {name:<44} {r["f1"]:>6.4f}  {avg_p_str:>6}  '
              f'{r["recall"]:>6.4f}  {r["fpr"]:>6.4f}  '
              f'{r.get("tp", 0):>9,}{flag}')
        print(f'    positives={r["positives_in_test"]:,}/{r["test_size"]:,} '
              f'({pct:.3f}%)  '
              f'TP={r.get("tp",0):,}  FP={r.get("fp",0):,}  '
              f'FN={r.get("fn",0):,}  TN={r.get("tn",0):,}')
    print('=' * 84)

    f1_vals          = [r['f1'] for r in results]
    f1_range         = max(f1_vals) - min(f1_vals)
    low_pct_folds    = [r['held_out'] for r in results
                        if r.get('positives_in_test_pct', 100) < 1.0]

    if low_pct_folds:
        print()
        short = [f.split('_')[0] for f in low_pct_folds]
        print(f'  NOTE: {", ".join(short)} has <1% attack rows in its test set — '
              'its F1 is not directly comparable to the other folds. '
              'Use Average Precision and TP count instead.')

    if f1_range > 0.25:
        print()
        print(f'  *** HIGH F1 VARIANCE: range = {f1_range:.4f} (> 0.25). ***')
        if low_pct_folds:
            # Re-check variance excluding imbalanced folds
            balanced_f1 = [r['f1'] for r in results
                           if r.get('positives_in_test_pct', 100) >= 1.0]
            if balanced_f1:
                bal_range = max(balanced_f1) - min(balanced_f1)
                print(f'  *** Excluding <1%-attack folds: F1 range = '
                      f'{bal_range:.4f}', end='')
                if bal_range > 0.25:
                    print(' — still high, possible attack-type generalisation failure.')
                else:
                    print(' — within acceptable range.')
    else:
        print(f'\n  F1 range = {f1_range:.4f} — no strong generalisation failure signal.')
    print()


def _print_lofo_summary(lofo_results: list):
    """Alias for backward compatibility."""
    _print_fold_table(
        lofo_results,
        'Leave-One-File-Out Results (leakage diagnostic — bundled samples)',
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    # Ensure Unicode characters print correctly on Windows (cp1252 console)
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass  # not critical; printing will still work with ASCII fallbacks

    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    parser = argparse.ArgumentParser(
        description='Logistic regression baseline + leakage diagnostics for SentinelNet'
    )
    parser.add_argument('--data-dir',
        default=os.environ.get(
            'SENTINELNET_RAW_DATA_DIR',
            os.path.join(_ROOT, 'data', 'samples'),
        ),
        help='Bundled sample_ CSV directory (default: data/samples/). '
             'Used by --split-mode stratified and leave-file-out.')
    parser.add_argument('--real-data-dir',
        default=os.path.join(_ROOT, 'data', 'CIC-IDS2018'),
        help='Real CSE-CIC-IDS2018 day CSV directory '
             '(default: data/CIC-IDS2018/). Used by --split-mode leave-day-out. '
             'A .cache/ subdirectory will be created here for parquet cache files.')
    parser.add_argument('--sample-frac', type=float, default=0.05,
        help='Fraction of rows to sample from each TRAINING file '
             '(default 0.05 = 5%%). The held-out test file is always used in full.')
    parser.add_argument('--split-mode',
        choices=['stratified', 'leave-file-out', 'leave-day-out'],
        default='stratified',
        help=('"stratified": stratified 80/20 on combined sample files (default). '
              '"leave-file-out": LOFO on bundled sample_ CSVs. '
              '"leave-day-out": LODO on real CIC-IDS2018 day files '
              '(reads --real-data-dir; parquet-caches each CSV exactly once).'))
    parser.add_argument('--skip-validation', action='store_true',
        help='Skip validation output and hard-fail decisions before '
             'leave-day-out. Cache is still built if not present. '
             'Not recommended unless files have already been validated.')
    parser.add_argument('--output-json', default=None,
        help='Path to write/update benchmark JSON for the frontend/API. '
             'leave-day-out results are MERGED into any existing file '
             '(preserving leave_file_out from Part 1) rather than overwriting.')
    args = parser.parse_args()

    if not _PARQUET_AVAILABLE and args.split_mode == 'leave-day-out':
        print('WARNING: pyarrow is not installed — parquet caching disabled. '
              'Install with: pip install pyarrow  '
              'Falling back to raw CSV reads (no per-fold speedup).')

    # -----------------------------------------------------------------------
    # Validate directories up-front
    # -----------------------------------------------------------------------
    if args.split_mode in ('stratified', 'leave-file-out'):
        if not os.path.isdir(args.data_dir):
            raise SystemExit(
                f'--data-dir not found: {args.data_dir}\n'
                'Pass --data-dir to a folder containing sample_ CSV files.'
            )
        csv_files = _discover_sample_files(args.data_dir)
        print(f'Sample files ({len(csv_files)}): '
              f'{[os.path.basename(f) for f in csv_files]}')

    elif args.split_mode == 'leave-day-out':
        if not os.path.isdir(args.real_data_dir):
            raise SystemExit(
                f'--real-data-dir not found: {args.real_data_dir}\n'
                'Pass --real-data-dir to the directory containing the real '
                'CSE-CIC-IDS2018 day CSV files (e.g. data/CIC-IDS2018/).'
            )
        day_files = _discover_real_day_files(args.real_data_dir)
        if not day_files:
            raise SystemExit(
                f'No CSV files found in --real-data-dir: {args.real_data_dir}'
            )
        print(f'Real day files ({len(day_files)}): '
              f'{[os.path.basename(f) for f in day_files]}')

    # -----------------------------------------------------------------------
    # Execute the chosen split mode
    # -----------------------------------------------------------------------
    primary           = None
    lofo_results      = None
    lodo_results      = None
    validation_report = None

    if args.split_mode == 'stratified':
        print('\nRunning stratified random split (80/20, fixed seed 42) …')
        primary = run_stratified(args.data_dir, args.sample_frac)
        _print_metrics_block(
            'Stratified Split — Logistic Baseline (sample files)', primary)
        print('\nRunning leave-one-file-out diagnostic (always computed with stratified) …')
        lofo_results = run_leave_file_out(args.data_dir, args.sample_frac)
        _print_lofo_summary(lofo_results)

    elif args.split_mode == 'leave-file-out':
        print('\nRunning leave-one-file-out on bundled sample files …')
        lofo_results = run_leave_file_out(args.data_dir, args.sample_frac)
        _print_lofo_summary(lofo_results)
        primary = {k: v for k, v in lofo_results[0].items()
                   if k in ('f1', 'precision', 'recall', 'fpr',
                             'positives_in_test', 'positives_in_test_pct', 'test_size')}

    elif args.split_mode == 'leave-day-out':
        cache_dir = os.path.join(args.real_data_dir, _CACHE_SUBDIR)

        if not args.skip_validation:
            # Build ref_cols from sample files for cross-schema check
            ref_cols = None
            if os.path.isdir(args.data_dir):
                sf = _discover_sample_files(args.data_dir)
                if sf:
                    h = pd.read_csv(sf[0], nrows=0, low_memory=False)
                    ref_cols = set(h.columns.str.strip().tolist())
            validation_report, cache_paths = validate_real_data_files(
                args.real_data_dir, ref_cols=ref_cols, hard_fail=True,
            )
        else:
            print('\n[--skip-validation] Skipping validation output. '
                  'Building/loading cache …')
            # Still need to build caches for LODO
            cache_paths = {}
            for path in _discover_real_day_files(args.real_data_dir):
                fn = os.path.basename(path)
                p, _ = _build_file_cache(path, cache_dir)
                cache_paths[fn] = p if p else path
            validation_report = {
                'passed': True,
                'warnings': ['Validation skipped by user (--skip-validation).'],
                'hard_failures': [],
                'files': [],
            }

        print('\nRunning leave-day-out on real CSE-CIC-IDS2018 files …')
        lodo_results = run_leave_day_out(
            args.real_data_dir, args.sample_frac, cache_paths)
        _print_fold_table(
            lodo_results,
            'Leave-Day-Out Results (real CSE-CIC-IDS2018 — '
            'dataset: cse-cic-ids2018-4day)',
        )

    # -----------------------------------------------------------------------
    # JSON output  (merge strategy for leave-day-out)
    # -----------------------------------------------------------------------
    if args.output_json:
        existing: dict = {}
        if os.path.exists(args.output_json):
            try:
                with open(args.output_json) as fh:
                    existing = json.load(fh)
            except Exception as e:
                print(f'Warning: could not parse existing {args.output_json}: {e}. '
                      'Starting fresh.')

        def _fold_to_json(r: dict) -> dict:
            avg_p = r.get('average_precision')
            return {
                'held_out':              r['held_out'],
                'train_files':           r['train_files'],
                'f1':                    float(r['f1']),
                'precision':             float(r['precision']),
                'recall':                float(r['recall']),
                'fpr':                   float(r['fpr']),
                'tp':                    int(r.get('tp', 0)),
                'fp':                    int(r.get('fp', 0)),
                'fn':                    int(r.get('fn', 0)),
                'tn':                    int(r.get('tn', 0)),
                'average_precision':     float(avg_p) if avg_p is not None else None,
                'positives_in_test':     int(r['positives_in_test']),
                'positives_in_test_pct': float(r.get('positives_in_test_pct', 0)),
                'test_size':             int(r['test_size']),
            }

        if args.split_mode in ('stratified', 'leave-file-out'):
            existing.update({
                'split_mode':     args.split_mode,
                'dataset':        'sample_files',
                'f1':             float(primary['f1']),
                'precision':      float(primary['precision']),
                'recall':         float(primary['recall']),
                'fpr':            float(primary['fpr']),
                'data_dir':       args.data_dir,
                'sample_frac':    args.sample_frac,
                'leave_file_out': [_fold_to_json(r) for r in lofo_results],
            })

        elif args.split_mode == 'leave-day-out':
            existing['leave_day_out'] = {
                'dataset':        'cse-cic-ids2018-4day',
                'real_data_dir':  args.real_data_dir,
                'sample_frac':    args.sample_frac,
                'validation_report': {
                    'passed':        validation_report['passed'],
                    'warnings':      validation_report['warnings'],
                    'hard_failures': validation_report['hard_failures'],
                    'files':         validation_report['files'],
                },
                'folds': [_fold_to_json(r) for r in lodo_results],
            }

        with open(args.output_json, 'w') as fh:
            json.dump(existing, fh, indent=2)
        print(f'Wrote benchmark JSON to {args.output_json}')


if __name__ == '__main__':
    main()

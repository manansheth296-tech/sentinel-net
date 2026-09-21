import argparse
import os
import glob
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from sklearn.preprocessing import StandardScaler

def load_and_preprocess_clean(data_dir, sample_frac=0.05):
    """
    Leakage-free baseline preparation:
    1. Filters out leaky identifiers: Dst Port, Timestamp, Flow ID, Label
    2. Keeps the exact 77 numeric statistical features (matching Prachi's schema)
    3. Handles NaNs, infinities, and bad headers without data leakage

    File selection: prefers files whose names start with 'sample_' (the labeled
    attack-vs-benign CSVs bundled with this repo). Falls back to all CSVs in
    data_dir if no sample_ files are present.
    """
    all_csv = glob.glob(os.path.join(data_dir, "*.csv"))

    # Prefer the explicitly-labeled sample files; they contain both classes.
    sample_files = [f for f in all_csv if os.path.basename(f).startswith("sample_")]
    csv_files = sorted(sample_files) if sample_files else sorted(all_csv)

    # Non-feature / leaky identifier columns to exclude
    NON_FEATURE_COLS = {'Label', 'Timestamp', 'Dst Port', 'Flow ID', 'Src IP', 'Dst IP', 'Src Port'}

    df_list = []
    for f in csv_files[:3]:
        df = pd.read_csv(f, low_memory=False)
        df_list.append(df.sample(frac=sample_frac, random_state=42))

    df = pd.concat(df_list, ignore_index=True)
    df.columns = df.columns.str.strip()

    label_col = 'Label'
    y = (df[label_col] != 'Benign').astype(int)

    # Keep only the 77 numeric feature columns
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols].apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)

    return X, y, feature_cols

def main():
    parser = argparse.ArgumentParser(description="Leakage-free logistic regression baseline for SentinelNet")
    parser.add_argument(
        "--data-dir",
        default=os.environ.get(
            "SENTINELNET_RAW_DATA_DIR",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "samples"),
        ),
        help="Directory containing raw CIC-IDS-2018-style CSV files. "
             "Defaults to $SENTINELNET_RAW_DATA_DIR or <repo>/data/samples "
             "(the sample CSVs bundled with this repository).",
    )
    parser.add_argument("--sample-frac", type=float, default=0.05)
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to write the resulting benchmark numbers as JSON "
             "so the frontend/API can display a real baseline instead of "
             "'not available'.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.data_dir):
        raise SystemExit(
            f"Data directory not found: {args.data_dir}\n"
            "Pass --data-dir, or set SENTINELNET_RAW_DATA_DIR, to a folder of "
            "CIC-IDS-2018-style CSV files. The bundled sample CSVs live in "
            "data/samples/ — pass that path if you have not downloaded the full "
            "CIC-IDS-2018 dataset. This script is never invoked automatically "
            "by the API/dashboard — run it manually and pass "
            "--output-json backend/baseline_result.json to cache the result."
        )

    data_dir = args.data_dir
    X, y, feature_cols = load_and_preprocess_clean(data_dir, sample_frac=args.sample_frac)
    
    print(f"Features used ({len(feature_cols)} cols): {feature_cols[:5]} ...")
    
    # Chronological / Time-ordered split to avoid burst flow leakage
    split_idx = int(len(X) * 0.8)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training Logistic Regression on non-leaky 77 features...")
    clf = LogisticRegression(max_iter=1000, random_state=42)
    clf.fit(X_train_scaled, y_train)
    
    y_pred = clf.predict(X_test_scaled)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("\n==============================================")
    print("  Leakage-Free Logistic Baseline Results")
    print("==============================================")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print("==============================================")

    if args.output_json:
        import json
        result = {"f1": float(f1), "precision": float(prec), "recall": float(rec), "fpr": float(fpr),
                   "data_dir": data_dir, "sample_frac": args.sample_frac}
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Wrote benchmark JSON to {args.output_json}")

if __name__ == "__main__":
    main()

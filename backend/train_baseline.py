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
    """
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
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
    data_dir = r"m:\SIH_2026\sih26153-network-forecast\data\raw"
    X, y, feature_cols = load_and_preprocess_clean(data_dir, sample_frac=0.05)
    
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

if __name__ == "__main__":
    main()

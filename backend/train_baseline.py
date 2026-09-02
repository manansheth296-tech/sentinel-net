import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import os
import glob

def load_and_preprocess(data_dir, sample_frac=0.05):
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
    df_list = []
    # We will use the first 3 files to get a good mix of attacks
    for f in csv_files[:3]:
        print(f"Loading {os.path.basename(f)}...")
        df = pd.read_csv(f, low_memory=False)
        # Random sample to train quickly on a laptop
        df = df.sample(frac=sample_frac, random_state=42)
        df_list.append(df)
        
    df = pd.concat(df_list, ignore_index=True)
    
    # Clean column names (remove leading/trailing spaces)
    df.columns = df.columns.str.strip()
    
    label_col = 'Label'
    if label_col not in df.columns:
        print("Label column not found! Available columns:", df.columns)
        return None, None
        
    # Drop rows with NaN or Inf
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    y_raw = df[label_col]
    # Binary classification: Benign (0) vs Attack (1)
    y = (y_raw != 'Benign').astype(int)
    
    # Drop the label
    X = df.drop(columns=[label_col])
    
    # Force convert to numeric (CIC-IDS-2018 often has strings in numeric cols due to bad CSV concatenation)
    X = X.apply(pd.to_numeric, errors='coerce')
    
    # Fill NaN and Inf with 0. 
    # Network stats often have Inf for bytes/sec when duration is 0. 
    # Filling with 0 is standard practice for this dataset in baseline models.
    X = X.fillna(0)
    
    return X, y

def main():
    data_dir = r"m:\SIH_2026\sih26153-network-forecast\data\raw"
    print("Preprocessing data...")
    X, y = load_and_preprocess(data_dir, sample_frac=0.05)
    
    if X is None:
        return
        
    print(f"Total samples: {len(X)}")
    print(f"Attack samples: {y.sum()} / {len(y)}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training Logistic Regression baseline...")
    clf = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
    clf.fit(X_train_scaled, y_train)
    
    print("Evaluating...")
    y_pred = clf.predict(X_test_scaled)
    
    f1 = f1_score(y_test, y_pred, zero_division=0)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("\n==============================================")
    print("   Logistic Regression Baseline Results")
    print("==============================================")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print("==============================================")

if __name__ == "__main__":
    main()

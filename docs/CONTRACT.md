# SentinelNet — Data & Model Contract

## 1. Feature Schema (77 Numeric Statistical Features)
To prevent data leakage, all identifier and target columns are excluded:
- **Excluded Non-Feature Columns:** `Label`, `Timestamp`, `Dst Port`, `Src IP`, `Dst IP`, `Flow ID`, `Src Port`
- **Included Statistical Features (77 columns):**
  `Protocol`, `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts`,
  `Fwd Pkt Len Max/Min/Mean/Std`, `Bwd Pkt Len Max/Min/Mean/Std`, `Flow Byts/s`, `Flow Pkts/s`,
  `Flow IAT Mean/Std/Max/Min`, `Fwd IAT Tot/Mean/Std/Max/Min`, `Bwd IAT Tot/Mean/Std/Max/Min`,
  `Fwd/Bwd PSH Flags`, `Fwd/Bwd URG Flags`, `Fwd/Bwd Header Len`, `Fwd/Bwd Pkts/s`,
  `Pkt Len Min/Max/Mean/Std/Var`, `FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Cnt`, `Down/Up Ratio`,
  `Pkt Size Avg`, `Fwd/Bwd Seg Size Avg`, `Subflow Fwd/Bwd Pkts/Byts`, `Init Fwd/Bwd Win Byts`,
  `Fwd Act Data Pkts`, `Fwd Seg Size Min`, `Active Mean/Std/Max/Min`, `Idle Mean/Std/Max/Min`.

## 2. World Model Sequence Input Shape
- **Temporal Window Aggregation:** Each time window aggregates the 77 features into a **156-dimensional state vector** $S_t$ (77 Means + 77 Standard Deviations + Flow Counts + Active Flow Stats).
- **Sequence Tensor Shape:** `(Batch_Size, 20, 156)` representing 20 consecutive time-step windows.

## 3. Evaluation & Benchmarking Protocol
- **No Random Splitting:** To avoid duplicate flow leakage from synchronized attack bursts, evaluation must use **chronological time splits** or **cross-file (out-of-distribution) splits**.
- **Metrics Tracked:** F1-Score, Precision, Recall, False Positive Rate (FPR).

## 4. Backend Inference Output Schema (`backend/engine.py`)
```json
{
  "infiltration_timeline": [
    {"window_start": "2018-02-14T10:00:00", "probability": 0.12},
    {"window_start": "2018-02-14T10:01:00", "probability": 0.34},
    {"window_start": "2018-02-14T10:02:00", "probability": 0.63},
    {"window_start": "2018-02-14T10:03:00", "probability": 0.88}
  ],
  "predicted_stage": "Lateral Movement",
  "stage_probs": {
    "Reconnaissance": 0.05,
    "Initial Access": 0.10,
    "Lateral Movement": 0.55,
    "Command & Control": 0.20,
    "Exfiltration": 0.10
  },
  "top_features": [
    {"feature": "SYN Flag Count", "importance": 0.31},
    {"feature": "Fwd IAT Mean", "importance": 0.22},
    {"feature": "Flow Duration", "importance": 0.15}
  ],
  "flagged_flows": [
    {"src_ip": "192.168.10.5", "dst_ip": "192.168.10.50", "risk_score": 0.81}
  ],
  "benchmark": {
    "world_model":       {"f1": 0.84, "precision": 0.93, "recall": 0.77, "fpr": 0.017},
    "logistic_baseline": {"f1": 0.61, "precision": 0.68, "recall": 0.56, "fpr": 0.082}
  }
}
```

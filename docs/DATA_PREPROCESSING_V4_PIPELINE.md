# SentinelNet — Data Preprocessing & V4 Pipeline
### High-Throughput Preprocessing, Feature Engineering & Validation Guide

---

## 1. Environment & Setup

1. Navigate to the project root directory:
   ```bash
   cd sentinel-net-main
   ```

2. Activate the virtual environment:
   - **Windows:**
     ```bash
     .venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     source .venv/bin/activate
     ```

3. Install project dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 2. Directory Architecture & Required Assets

### Preprocessing & Testing Modules
```text
sentinel-net-main/
├── backend/
│   └── data_prep.py          # Core temporal windowing and state vector extraction
├── data/
│   ├── clean_dataset.py      # Cleans NaN, Inf, and duplicate headers
│   └── convert_to_v4.py      # Column renaming & V4 schema alignment
└── tests/
    └── test_data_prep.py     # 39-point unit & integration test suite
```

### Model Artifacts (`model/`)
Ensure the following V4 model files are present before executing inference:
- `world_model_v4_best.pt` (Trained LSTM world model weights)
- `scaler_v4.pkl` (Fitted StandardScaler for 156-dim features)
- `preprocessing.py`
- `inference.py`
- `export_bundle_v4.json`

---

## 3. Dataset Preprocessing Execution

### Step 3.1: Raw Dataset Placement
Place raw CIC-IDS-2018 CSV capture files in the raw data directory:
```text
data/raw/03-01-2018.csv
```

---

### Step 3.2: Convert to V4 Schema
Standardize raw CICFlowMeter columns into the V4 specification:
```bash
python data/convert_to_v4.py --input data/raw/03-01-2018.csv --output data/raw/03-01-2018_v4.csv
```
*Expected Output:* `80 Columns | 331,125 Rows`

---

### Step 3.3: Clean Dataset
Sanitize numeric fields, strip repeated CSV headers, and handle zero-duration flows:
```bash
python data/clean_dataset.py --input data/raw/03-01-2018_v4.csv
```
The cleaned dataset will be output to:
```text
data/clean/03-01-2018_v4_clean.csv
```

#### Cleaning Pipeline Operations:
- Strips repeated header rows inserted by distributed capture tools.
- Normalizes CIC-IDS-2018 column headers to canonical names.
- Coerces numeric columns (`pd.to_numeric(errors="coerce")`).
- Maps `NaN` and $\pm\infty$ values to `0` without dropping valid flows.
- Retains zero-duration flows to preserve micro-burst attacks.

---

## 4. Verification & Validation

### 4.1 Schema Consistency Check
Verify that all 77 numeric features required by the model are present:
```bash
python -c "import pandas as pd; from backend.data_prep import RAW_FEATURE_NAMES; df=pd.read_csv('data/clean/03-01-2018_v4_clean.csv', nrows=1); missing=[x for x in RAW_FEATURE_NAMES if x not in df.columns]; print('Columns:', len(df.columns)); print('Missing:', missing); print('Missing count:', len(missing))"
```
*Target Result:* `Columns: 81`, `Missing: []`, `Missing count: 0`.

---

### 4.2 Automated Test Suite
Execute the full test suite with pytest:
```bash
python -m pytest tests/test_data_prep.py -v
```

#### Test Verification Coverage (39/39 Passing):
- **77-Feature Schema:** Exact raw column mapping and verification.
- **156-Dim State Vectors:** Interleaved mean (77) + std (77) + metadata (2: unique dst ports, flow count).
- **Sequence Construction:** Sliding window of 20 consecutive state vectors $\to (20, 156)$.
- **Data Hygiene:** Zero `NaN` or `Inf` propagation; zero data leakage across splits.
- **Chronological Integrity:** Temporal sort validation without refitting pre-trained scalers.

---

## 5. End-to-End V4 Tensor Pipeline

```
77 Raw Flow Features
       ↓
Statistical Aggregation: Mean (77) + Std (77)
       ↓
Metadata Enrichment: Unique Destination Ports (1) + Flow Count (1)
       ↓
156-Dimensional State Vector S_t
       ↓
Temporal Stacking (20 Consecutive Timesteps)
       ↓
Input Tensor: (20, 156)
       ↓
V4 Pre-Fitted StandardScaler
       ↓
V4 LSTM World Model (P(S_t+1 | S_t))
```

> [!NOTE]
> The exact feature ordering in the 156-dimensional vector must remain unchanged to preserve alignment with `scaler_v4.pkl` and `world_model_v4_best.pt`.

---

## 6. Baseline Validation Summary (Reference: `03-01-2018.csv`)

| Metric / Checkpoint | Value | Status |
|---|:---:|:---:|
| **Raw Input Rows** | 331,125 | — |
| **Repeated Headers Stripped** | 25 | Verified |
| **Clean Output Rows** | 331,100 | Verified |
| **Residual NaN / Inf** | 0 | Clean |
| **Raw Model Features** | 77 | Aligned |
| **Engineered State Dimension** | 156 | Aligned |
| **Sequence Length ($T$)** | 20 | Aligned |
| **PyTest Suite** | 39 / 39 Passed | **PASS** |

> **Conclusion:** The preprocessing pipeline is fully validated and operational for V4 model training, benchmarking, and real-time inference.
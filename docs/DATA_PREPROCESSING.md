# SentinelNet — Data Preprocessing & V4 Pipeline

## 1. Setup

Open terminal in the project root:

```bash
cd sentinel-net-main
```

Activate the virtual environment:

### Windows

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 2. Required Files

The preprocessing implementation consists of:

```text
backend/
└── data_prep.py

data/
├── convert_to_v4.py
└── clean_dataset.py

tests/
└── test_data_prep.py
```

The V4 model artifacts should be present in:

```text
model/
├── world_model_v4_best.pt
├── scaler_v4.pkl
├── preprocessing.py
├── inference.py
└── export_bundle_v4.json
```

---

## 3. Dataset

Place the raw CIC-IDS-2018 CSV here:

```text
data/raw/03-01-2018.csv
```

---

## 4. Convert Dataset

Run:

```bash
python data\convert_to_v4.py --input data\raw\03-01-2018.csv --output data\raw\03-01-2018_v4.csv
```

Expected output:

```text
Columns: 80
Rows: 331125
```

---

## 5. Clean Dataset

Run:

```bash
python data\clean_dataset.py --input data\raw\03-01-2018_v4.csv
```

The cleaned file will be generated at:

```text
data/clean/03-01-2018_v4_clean.csv
```

The cleaning pipeline:

- Removes repeated header rows
- Normalizes CIC-IDS-2018 column names
- Converts numeric values using `pd.to_numeric(errors="coerce")`
- Converts NaN and Infinity values to `0`
- Does not drop valid rows because of NaN/Infinity
- Preserves zero-duration flows

For the tested `03-01-2018.csv`:

```text
Raw rows:          331,125
Headers removed:       25
Clean rows:        331,100
NaN remaining:           0
Inf remaining:           0
```

---

## 6. Verify Feature Schema

Run:

```bash
python -c "import pandas as pd; from backend.data_prep import RAW_FEATURE_NAMES; df=pd.read_csv('data/clean/03-01-2018_v4_clean.csv', nrows=1); missing=[x for x in RAW_FEATURE_NAMES if x not in df.columns]; print('Columns:', len(df.columns)); print('Missing:', missing); print('Missing count:', len(missing))"
```

Expected:

```text
Columns: 81
Missing: []
Missing count: 0
```

The pipeline uses **77 raw numeric model features**.

---

## 7. Run Tests

Run:

```bash
python -m pytest tests/test_data_prep.py -v
```

Expected:

```text
39 passed
```

The tests verify:

- 77 raw feature schema
- 156-dimensional state vectors
- V4 interleaved mean/std feature ordering
- 20-state sequence construction
- NaN → 0
- Infinity → 0
- zero-duration flows
- repeated-header removal
- chronological ordering
- no metadata leakage
- scaler is not refitted
- final sequence contains no NaN/Infinity
- end-to-end `(20, 156)` compatibility

---

## 8. V4 Model Input

The final temporal representation is:

```text
77 raw features
        ↓
mean(77) + std(77)
        ↓
unique_dst_ports + flow_count
        ↓
156-dimensional state
        ↓
20 consecutive states
        ↓
(20, 156)
        ↓
V4 scaler
        ↓
V4 LSTM/world model
```

The V4 feature ordering must remain unchanged because the trained scaler/model expects the same 156-dimensional feature layout.

---

## 9. Current Validation Status

Tested successfully on:

```text
03-01-2018.csv
```

Results:

```text
Raw rows:             331,125
Clean rows:           331,100
Repeated headers:          25
NaN after cleaning:         0
Inf after cleaning:         0
Raw model features:        77
State dimension:           156
Sequence length:            20
Test cases passed:         39/39
```

**Status: PASS**

The preprocessing pipeline is ready for model integration/retraining.
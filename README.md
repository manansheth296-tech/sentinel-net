# SentinelNet: AI-Based Network Attack Forecasting

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Framework](https://img.shields.io/badge/PyTorch-LSTM-red.svg)](https://pytorch.org/)
[![UI](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B.svg)](https://streamlit.io/)
[![Execution](https://img.shields.io/badge/Offline-100%25-green.svg)](#offline-deployment)

> **SIH 2026 · Problem Statement SIH26153 (NTRO)**  
> Real-time, offline network attack forecasting system utilizing sequence dynamics modeling ($P(S_{t+1} \mid S_t)$) to project multi-step infiltration probability timelines and MITRE ATT&CK progression.

---

## 📌 Key Capabilities

- **State Dynamics Modeling ($P(S_{t+1} \mid S_t)$):** Learns temporal traffic evolution using LSTM networks rather than simple static classification.
- **Multi-Step Horizon Rollout:** Projects attack trajectory up to $K$ windows into the future.
- **MITRE ATT&CK Stage Mapping:** Maps anomalous traffic behavior to formal MITRE cyber kill chain stages (`Reconnaissance` $\to$ `Initial Access` $\to$ `Lateral Movement` $\to$ `Command & Control` $\to$ `Exfiltration`).
- **Explainability (XAI):** Uses SHAP (SHapley Additive exPlanations) and permutation importance for localized flag, port, and flow feature attribution.
- **Comparative Benchmarking:** Validates world model performance against a standard `LogisticRegression` baseline on $F_1$-score, precision, recall, and false positive rate (FPR).
- **100% Offline Architecture:** Requires zero external cloud APIs, running fully self-contained on local hardware.

---

## 🗂 Project Directory Structure

```text
sih26153-network-forecast/
├── backend/
│   ├── __init__.py
│   ├── data_prep.py              # Sequence windowing & state vector extraction
│   ├── engine.py                 # Core inference orchestration & API contract output
│   ├── explain.py                # SHAP / Feature importance explainability engine
│   ├── mitre_mapping.py          # Rule-based dataset to MITRE stage mapper
│   ├── server.py                 # FastAPI REST API server (/api/analyze)
│   └── train_baseline.py         # Logistic regression baseline & benchmark harness
├── frontend/
│   ├── public/                   # Static assets (favicons, SVG icons)
│   ├── src/
│   │   ├── api/                  # API client (analyze.js)
│   │   ├── components/           # UI components (InfiltrationChart, RiskGauge, etc.)
│   │   ├── context/              # Application & Toast context
│   │   ├── views/                # Dashboard, LiveAnalysis, Findings, Settings, Profile
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js            # Vite reverse proxy to FastAPI backend
│   └── index.html
├── model/
│   ├── __init__.py
│   ├── export_bundle_v4.json     # Serialized model metadata & evaluation stats
│   ├── inference.py              # PyTorch inference routine
│   ├── preprocessing.py          # Feature transformation helpers
│   ├── scaler_v4.pkl             # Pre-fitted 156-dim StandardScaler
│   ├── world_model_v4_best.pt    # Trained LSTM weights (1.3 MB)
│   └── README_LSTM_WORLD_MODEL.md
├── app/
│   ├── __init__.py
│   └── streamlit_app.py          # Standalone offline Streamlit UI dashboard
├── data/
│   ├── __init__.py
│   ├── clean_dataset.py          # Header removal, NaN/Inf handling
│   ├── convert_to_v4.py          # CIC-IDS-2018 to V4 feature schema alignment
│   ├── sample_test.csv           # Pre-validated sample capture for demo runs
│   ├── raw/                      # Raw capture CSV drop location
│   └── processed/                # Normalized tensor splits
├── docs/
│   ├── CONTRACT.md               # Strict feature schema & JSON contract definition
│   ├── DATA_PREPROCESSING.md     # Detailed data engineering manual
│   └── architecture.md           # Technical architecture specification
├── tests/
│   └── test_data_prep.py         # Unit & integration test suite
├── .gitignore                    # Git ignore file
├── requirements.txt              # Unified project dependencies
└── README.md                     # Repository documentation
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/manansheth296-tech/sentinel-net.git
cd sih26153-network-forecast

# Create and activate Python virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux/macOS

# Install Python dependencies
pip install -r requirements.txt

# Install Frontend dependencies
cd frontend
npm install
cd ..
```

### 3. Run Preprocessing & Feature Extraction
```bash
# Convert raw CIC-IDS-2018 CSV
python data/convert_to_v4.py --input data/raw/03-01-2018.csv --output data/raw/03-01-2018_v4.csv

# Clean and sanitize dataset
python data/clean_dataset.py --input data/raw/03-01-2018_v4.csv
```

### 4. Run Test Suite
```bash
python -m pytest tests/test_data_prep.py -v
```

### 5. Launch Full Stack (FastAPI Backend + React Frontend)

**Terminal 1 — Backend (Port 8000):**
```bash
uvicorn backend.server:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend (Port 5173):**
```bash
cd frontend
npm run dev
```

*(Optional) Launch Standalone Streamlit Dashboard:*
```bash
streamlit run app/streamlit_app.py
```

---

## 📊 Model Contract Schema

Inference execution via `backend/engine.py` returns a strict JSON payload:

```json
{
  "infiltration_timeline": [
    { "window_start": "2018-02-14T10:00:00", "probability": 0.12 },
    { "window_start": "2018-02-14T10:01:00", "probability": 0.63 }
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
    { "feature": "SYN Flag Count", "importance": 0.31 },
    { "feature": "Fwd IAT Mean", "importance": 0.22 }
  ],
  "flagged_flows": [
    { "src_ip": "192.168.10.5", "dst_ip": "192.168.10.50", "risk_score": 0.81 }
  ],
  "benchmark": {
    "world_model":       { "f1": 0.84, "precision": 0.93, "recall": 0.77, "fpr": 0.017 },
    "logistic_baseline": { "f1": 0.61, "precision": 0.68, "recall": 0.56, "fpr": 0.082 }
  }
}
```

---

## 🔒 Offline Deployment

This application operates completely standalone without external network calls or cloud dependencies:
- **Weights & Scaler:** Loaded locally from `model/`.
- **Explainability:** Computed locally via `shap` background samples.
- **Frontend Dashboard:** Runs locally on `http://localhost:8501`.

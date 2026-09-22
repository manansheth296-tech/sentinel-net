<div align="center">

<!-- BANNER -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,11,20&height=180&section=header&text=SentinelNet%20🛡️&fontSize=42&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=AI-Based%20Network%20Attack%20Forecasting%20%7C%20SIH26153&descSize=18&descAlignY=58" width="100%"/>

<!-- BADGES -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/React%20%2B%20Vite-Dashboard-646CFF?style=for-the-badge&logo=vite&logoColor=white"/>
  <img src="https://img.shields.io/badge/PyTorch-LSTM%20World%20Model-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white"/>
  <img src="https://img.shields.io/badge/SHAP-Explainable%20AI-8A2BE2?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Stage%20Mapping-CC0000?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/SIH%202026-PS%2026153%20·%20NTRO-FF6B35?style=for-the-badge"/>
</p>

<!-- LINKS -->
<p align="center">
  <a href="https://youtu.be/UD31H2vVHIA">
    <img src="https://img.shields.io/badge/▶️%20Watch-Demo%20Video-red?style=for-the-badge&logo=youtube"/>
  </a>
  &nbsp;
  <a href="https://github.com/manansheth296-tech/sentinel-net">
    <img src="https://img.shields.io/badge/GitHub-sentinel--net-181717?style=for-the-badge&logo=github"/>
  </a>
  &nbsp;
  <a href="#-team">
    <img src="https://img.shields.io/badge/Team-SentinelNet-blue?style=for-the-badge"/>
  </a>
</p>

<br/>

> **SentinelNet** is a network-traffic analysis platform built for **SIH26153 (National Technical Research Organisation — NTRO)**. It pairs a **FastAPI inference service** with a **React/Vite dashboard** (and a standalone Streamlit alternative) to turn raw CICFlowMeter-style flow captures into a **forward-looking security signal**: it forecasts near-future infiltration risk with an LSTM world model, maps the forecast onto a **MITRE ATT&CK** stage, and explains every score with **SHAP** feature attribution — end to end, from a `.csv`/`.pcap` upload to an explained, actionable dashboard view.

<br/>

<img src="assets/architecture_diagram.png" width="100%" alt="SentinelNet LSTM World Model Architecture"/>

<br/>

> ⚠️ **Project status: internal prototype / hackathon demonstration.** The current model is trained on a generic *any-attack* target, not an infiltration-only target. See [Model Limitations](#️-model-limitations--honest-disclosure) before treating results as operational.

</div>

---

## 📋 Table of Contents

<details>
<summary>Click to expand</summary>

- [🎯 Problem Statement](#-problem-statement)
- [✨ Features](#-features)
- [🏗️ System Architecture](#️-system-architecture)
- [🧠 Traffic-to-State Representation](#-traffic-to-state-representation)
- [🤖 The LSTM World Model](#-the-lstm-world-model)
- [🔁 Forecasting & MITRE Stage Mapping](#-forecasting--mitre-stage-mapping)
- [🔬 Explainability — SHAP](#-explainability--shap)
- [🔌 Backend API Contract](#-backend-api-contract)
- [📁 Repository Layout](#-repository-layout)
- [⚡ Quick Start](#-quick-start)
- [🧪 Testing](#-testing)
- [🩹 Troubleshooting](#-troubleshooting)
- [📈 Benchmark Results](#-benchmark-results)
- [⚠️ Model Limitations — Honest Disclosure](#️-model-limitations--honest-disclosure)
- [🎥 Demo Video & Screenshots](#-demo-video--screenshots)
- [🛠️ Tech Stack](#️-tech-stack)
- [🗺️ Roadmap](#️-roadmap)
- [👥 Team](#-team)
- [📄 License](#-license)

</details>

---

## 🎯 Problem Statement

**SIH26153** · National Technical Research Organisation (NTRO) · Software

Traditional intrusion detection tools classify individual network flows **after the fact**, one snapshot at a time, with no memory of how traffic behaviour got there and no forward-looking view of where it's headed. That leaves defenders reactive.

**SentinelNet reframes intrusion detection as a forecasting problem.** Traffic is modelled as an evolving sequence of behavioural states; a two-layer LSTM **world model** learns how that sequence transitions, forecasts risk ahead of time, maps the forecast to a recognised MITRE ATT&CK kill-chain stage, and explains *why* — surfaced through a live dashboard an analyst can actually use.

---

## ✨ Features

- 📤 Upload `.csv` or `.pcap` files directly from the web dashboard
- 🧹 Cleans and normalizes CICFlowMeter column names, repeated headers, missing values, and infinite values
- 🧩 Aggregates 77 raw numeric flow features into **156-dimensional temporal state vectors**
- 🔁 Feeds the latest 20 states into the **V4 LSTM world model**
- 🔮 Forecasts multiple future infiltration-risk probabilities (not just the current instant)
- 🗺️ Displays the predicted **MITRE ATT&CK stage**, per-stage probabilities, top contributing features, and flagged flows
- 📊 Surfaces **benchmark metrics** (world model vs. logistic-regression baseline) directly in the response
- ⚙️ Backend (FastAPI) and frontend (Vite/React) run independently, or together with the API serving the built frontend as static files
- 🖥️ A standalone **Streamlit dashboard** (`app/streamlit_app.py`) offers a no-frontend-build alternative for quick demos

---

## 🏗️ System Architecture

```
   Network capture / CICFlowMeter CSV or PCAP
                       │
                       ▼
              FastAPI  /api/analyze
                       │
                       ▼
       Column normalization & cleaning
   (repeated headers · missing/±inf values ·
    alternate CICFlowMeter column names)
                       │
                       ▼
   200-row windows → mean/std + unique_dst_ports + flow_count
                       │
                       ▼
             20 × 156 LSTM input sequence
                       │
                       ▼
   Risk forecast + MITRE stage + SHAP explanations
                       │
                       ▼
              React / Vite dashboard
          (or the standalone Streamlit app)
```

**State construction, precisely:**

```
77 raw CICFlowMeter features
   → mean (77) + standard deviation (77)                = 154
   → unique_dst_ports (1) + flow_count (1)               =   2
   ─────────────────────────────────────────────────────────
   = 156-dimensional behavioural state

20 consecutive states → LSTM input shape (20, 156)
```

The deployed **V4 bundle** uses fixed **200-row pseudo-windows** rather than true timestamp-based windows, because the training data mirror doesn't provide a reliable per-row timestamp. This is a deliberate, disclosed substitution — not a hidden assumption — and it's documented formally in [`docs/CONTRACT.md`](docs/CONTRACT.md).

---

## 🧠 Traffic-to-State Representation

`backend/data_prep.py` (mirrored by `model/preprocessing.py` on the inference side) implements the cleaning contract:

1. Reads UTF-8 CSV data and strips header whitespace
2. Normalizes common alternate CICFlowMeter column names
3. Removes repeated header rows that sometimes appear mid-file in raw captures
4. Excludes identifiers/labels from the numeric model input — `Label`, `Timestamp`, `Flow ID`, IP addresses, source/destination ports
5. Coerces model features to numeric and replaces `NaN` / `+inf` / `-inf` with `0`, **without dropping rows**
6. Preserves file order and assigns consecutive 200-row windows (current V4 checkpoint)
7. Aggregates each window into a 156-D state and takes the **latest 20 states**
8. Applies the **pre-trained `StandardScaler`** (`model/scaler_v4.pkl`) — it is *never* fit on uploaded data

> ⚠️ The training data did not contain usable destination-port values, so `unique_dst_ports` was effectively always zero during training. Real port-diversity signal should be reintroduced in a retrained checkpoint before production use.

---

## 🤖 The LSTM World Model

A two-layer LSTM (input 156 → hidden 128), followed by dropout, layer normalisation, and **two prediction heads** sharing one representation:

| Head | Shape | Purpose |
|---|---|---|
| **State Prediction Head** | Linear 128 → ReLU → Dropout → Linear 156 | Forces the model to learn genuine traffic-transition dynamics, not just memorise a label |
| **Infiltration Head** | Linear 64 → ReLU → Dropout → Linear 1 → Sigmoid | Converts the learned temporal representation into a security-relevant risk score |

**Joint training objective:**

```
L = MSE(Ŝₜ₊₁, Sₜ₊₁) + λ · BCEWithLogitsLoss(ŷ, y),   λ = 1.0
```

Class imbalance (benign traffic dominates) is corrected with `pos_weight = N_negative / N_positive` inside the BCE loss. Full architecture, training configuration, and evaluation notes for the checked-in checkpoint live in [`model/README_LSTM_WORLD_MODEL.md`](model/README_LSTM_WORLD_MODEL.md) and [`docs/MODEL_DECISION.md`](docs/MODEL_DECISION.md).

The **three model artifacts must always come from the same training run** and be swapped together:

```
model/world_model_v4_best.pt     # LSTM checkpoint
model/scaler_v4.pkl              # matching 156-D StandardScaler
model/export_bundle_v4.json      # feature order + config used at inference time
```

Mixing artifacts from different runs can silently produce invalid predictions with no obvious shape error — this is called out explicitly in the troubleshooting section below.

---

## 🔁 Forecasting & MITRE Stage Mapping

Rather than scoring only the current instant, `backend/engine.py` rolls the model forward autoregressively: the predicted next state is appended to the 20-state window, the oldest state is dropped, and the updated sequence is fed back through the model to generate the next forecast — producing an **infiltration timeline** across several future windows instead of a single number.

**The LSTM does not directly classify the MITRE stage.** Each forecasted state is instead mapped to a stage in `backend/mitre_mapping.py` via **nearest-centroid matching** (Euclidean distance to per-stage centroids built from scaled training-state representations):

| Dataset Behaviour | MITRE ATT&CK Interpretation |
|---|---|
| PortScan | Reconnaissance |
| FTP / SSH Bruteforce | Credential Access / Initial Access |
| Web Attack | Initial Access |
| Infiltration | Lateral Movement |
| Bot / Botnet | Command & Control |
| DoS / DDoS | Impact |

> MITRE mapping is partly heuristic and can rely on file-level attack-family metadata from training rather than a purely traffic-derived per-flow stage — disclosed here rather than presented as ground truth.

---

## 🔬 Explainability — SHAP

`backend/explain.py` attributes the infiltration logit to input features using a **SHAP GradientExplainer**, aggregated by mean absolute contribution across the 20 temporal steps to surface the top contributing features per prediction. If SHAP is unavailable or returns an unexpected output shape, the module falls back to a **from-scratch permutation-importance implementation** — explainability never silently fails, it degrades gracefully.

---

## 🔌 Backend API Contract

Full contract and feature list: [`docs/CONTRACT.md`](docs/CONTRACT.md)

### `GET /api/health`

```bash
curl http://localhost:8000/api/health
```
```json
{"status": "healthy", "service": "sentinelnet-backend"}
```

### `POST /api/analyze`

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@path/to/flows.csv"
```

Accepts `.csv` or `.pcap`. Returns **HTTP 400** for unsupported extensions, **HTTP 500** if inference fails (with a safe fallback response — see [Model Limitations](#️-model-limitations--honest-disclosure)).

```json
{
  "infiltration_timeline": [
    {"window_start": "12:00:10", "probability": 0.63}
  ],
  "predicted_stage": "Initial Access",
  "stage_probs": {
    "Reconnaissance": 0.05,
    "Initial Access": 0.65,
    "Lateral Movement": 0.05,
    "Command & Control": 0.05,
    "Impact": 0.05
  },
  "top_features": [
    {"feature": "SYN Flag Count", "importance": 0.31}
  ],
  "flagged_flows": [
    {"src_ip": "192.168.10.5", "dst_ip": "192.168.10.50", "risk_score": 0.81}
  ],
  "benchmark": {
    "world_model": {"f1": 0.8403, "precision": 0.9304, "recall": 0.7662, "fpr": 0.0167},
    "logistic_baseline": {"f1": 0.612, "precision": 0.684, "recall": 0.554, "fpr": 0.082}
  }
}
```

---

## 📁 Repository Layout

```
sentinel-net/
│
├── app/
│   ├── __init__.py
│   └── streamlit_app.py            # Standalone Streamlit dashboard (no frontend build needed)
│
├── backend/
│   ├── __init__.py
│   ├── api.py                      # FastAPI app — /api/analyze, /api/health, serves frontend/ as static
│   ├── data_prep.py                # CSV cleaning + 156-D state construction
│   ├── engine.py                   # Cached model inference, K-step rollout, response assembly
│   ├── explain.py                  # SHAP GradientExplainer + permutation-importance fallback
│   ├── mitre_mapping.py            # Nearest-centroid MITRE ATT&CK stage mapping
│   ├── train_baseline.py           # Trains the logistic-regression comparison baseline
│   └── baseline_result.json        # Stored baseline metrics used in the API's benchmark block
│
├── data/
│   ├── samples/                    # Pre-validated sample captures for demoing without live traffic
│   ├── __init__.py
│   ├── clean_dataset.py            # Dataset cleaning utilities
│   ├── convert_to_v4.py            # Feature-format converter for the V4 pipeline
│   └── download.py                 # Dataset acquisition helper
│
├── model/
│   ├── __init__.py
│   ├── inference.py                # V4 LSTM inference wrapper
│   ├── preprocessing.py            # Model-side preprocessing (mirrors backend/data_prep.py)
│   ├── export_bundle_v4.json       # Feature order + model configuration
│   ├── scaler_v4.pkl               # 156-D StandardScaler (must match the checkpoint)
│   ├── world_model_v4_best.pt      # V4 checkpoint
│   └── README_LSTM_WORLD_MODEL.md  # Model architecture & evaluation notes (handoff doc)
│
├── frontend/
│   ├── src/                        # React dashboard source
│   ├── public/                     # Static assets (icons, favicons)
│   ├── package.json
│   └── vite.config.js              # Dev-server port + /api proxy to the FastAPI backend
│
├── tests/
│   └── test_data_prep.py           # Preprocessing test suite
│
├── docs/
│   ├── CONTRACT.md                 # Data + API response contract (source of truth)
│   ├── DATA_PREPROCESSING.md       # Preprocessing design notes
│   ├── DATA_PREPROCESSING_V4_PIPELINE.md
│   ├── MODEL_DECISION.md           # Why the V4 LSTM world model was chosen
│   ├── SIH26153_References.txt     # Problem-statement references
│   └── SIH26153_Team_Execution_*.md
│
├── assets/                         # README screenshots
│   ├── architecture_diagram.png
│   └── leave_day_out_baseline.png
│
├── requirements.txt
└── README.md
```

> 🗒️ **Note:** this project has no training notebook checked into the repository — model training happens via `backend/train_baseline.py` (baseline) plus the offline LSTM training run that produced the `model/` artifacts, documented in `model/README_LSTM_WORLD_MODEL.md` and `docs/MODEL_DECISION.md`.

---

## ⚡ Quick Start

### Requirements
- Python 3.11 or a compatible modern Python version
- Node.js 18+ and npm
- The Python dependencies in `requirements.txt`
- The matched V4 model artifacts in `model/` (`world_model_v4_best.pt`, `scaler_v4.pkl`, `export_bundle_v4.json`)

### 1. Create the Python environment

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> If PowerShell blocks activation, run the `.venv` Python executable directly or adjust your local execution policy.

### 2. Start the backend

```bash
python -m uvicorn backend.api:app --reload --port 8000
```

Run this from the **repository root** so `backend` is importable as a package. The API listens on `http://localhost:8000` — interactive docs at `http://localhost:8000/docs`.

Verify it's alive:

```bash
curl http://localhost:8000/api/health
```

### 3. Open the app

Because `backend/api.py` mounts `frontend/` as static files on the same server, you can go straight to:

```
http://127.0.0.1:8000
```

**— or —** run the frontend separately in dev mode for hot-reload while building:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` — Vite proxies `/api/*` to `http://localhost:8000`, so both services need to be running.

### 4. (Optional) Run the Streamlit alternative

```bash
streamlit run app/streamlit_app.py
```

Useful for a quick demo without building the React frontend at all.

### Frontend commands (from `frontend/`)

```bash
npm run dev       # Vite dev server, port 5173
npm run build     # Production build → frontend/dist
npm run preview   # Preview the production build locally
npm run lint      # Oxlint
```

The dashboard also includes a **Load sample** flow backed by static mock data (`frontend/src/data/mockResult.js`) — it works without the backend running, which is handy for a quick UI walkthrough during judging.

---

## 🧪 Testing

```bash
python -m pytest tests/test_data_prep.py -v
```

Covers column normalization, repeated-header removal, `NaN`/infinity handling, zero-duration flows, chronological windowing, metadata exclusion, state dimensions, and sequence construction. A full inference test additionally requires a valid, matching `model/scaler_v4.pkl`.

Frontend validation:

```bash
cd frontend
npm run lint
npm run build
```

---

## 🩹 Troubleshooting

**`FileNotFoundError` for `scaler_v4.pkl`**
Place the scaler from the *same training run* as `world_model_v4_best.pt` at `model/scaler_v4.pkl`. Don't rename an unrelated scaler to satisfy the import.

**Dashboard can't reach the API**
Confirm the backend is on port `8000`, the frontend is on port `5173`, and requests go to `/api/analyze`. The proxy is configured in `frontend/vite.config.js`.

**Upload returns HTTP 400**
The backend checks the filename extension — only `.csv` and `.pcap` are accepted.

**Upload returns HTTP 500**
Check the FastAPI terminal for the traceback. Common causes: missing model artifacts, incompatible feature columns, malformed CSV, or a dependency missing from the active environment.

---

## 📈 Benchmark Results

| Metric | LSTM World Model | Logistic Regression Baseline |
|---|---|---|
| **F1 Score** | **0.8403** | 0.6120 |
| **Precision** | **0.9304** | 0.6840 |
| **Recall** | 0.7662 | 0.5540 |
| **False Positive Rate** | **0.0167** | 0.0820 |

Reported on a **chronological, per-file split** (`backend/train_baseline.py` → `backend/baseline_result.json`) to avoid the cross-file leakage that produces artificially inflated numbers on random splits. The team additionally stress-tested the baseline with a stricter **leave-day-out** cross-validation on the real CSE-CIC-IDS2018 data:

<p align="center">
<img src="assets/leave_day_out_baseline.png" width="90%" alt="Leave-Day-Out Cross-Validation results and honest evaluation notes"/>
</p>

**Honest findings from that stress test:**
- **Botnet zero-shot collapse (F1 = 0.0000)** when Botnet's only collection day is held out — an expected limitation of a small few-shot baseline, not a bug; Average Precision (0.5446) still shows meaningful ranking signal.
- **Severe base-rate imbalance** on the Web/Infiltration day (<0.04% attack rows) artificially depresses raw F1 even where recall is reasonable.
- **High cross-day F1 variance** (0.0000 → 0.9748) is expected and healthy — it's what a *non-leaking* split looks like, unlike a stratified random split that reported a deceptively near-perfect F1 (0.98+) purely because sample files were dominated by a specific class.

---

## ⚠️ Model Limitations — Honest Disclosure

- The target is **generic any-attack**, not a dedicated infiltration label — `infiltration_timeline` is an *attack-risk* forecast, not proof of infiltration specifically.
- MITRE stage mapping is **partly heuristic** and can rely on file-level attack-family metadata rather than a purely traffic-derived per-flow stage.
- The current checkpoint uses **200-row pseudo-windows**, not true time-based windows.
- The benchmark is based on a chronological per-file split; some file test slices contain few or no attack windows, and **infiltration-specific performance is weaker than aggregate performance**.
- The backend has a **safe fallback response** on inference exceptions — a fallback-shaped response should never be read as a successful prediction; check backend logs when results look suspicious.
- The checked-in V4 artifacts (`world_model_v4_best.pt`, `scaler_v4.pkl`, `export_bundle_v4.json`) **must remain a matched set** — replacing only one can silently produce invalid predictions.

Full handoff and evaluation detail: [`model/README_LSTM_WORLD_MODEL.md`](model/README_LSTM_WORLD_MODEL.md).

---

## 🎥 Demo Video & Screenshots

<div align="center">

### ▶️ [Watch the full demo walkthrough](https://youtu.be/UD31H2vVHIA)

<a href="https://youtu.be/UD31H2vVHIA">
<img src="https://img.shields.io/badge/YouTube-Full%20Demo%20Video-FF0000?style=for-the-badge&logo=youtube&logoColor=white"/>
</a>

</div>

<br/>

**Full architecture — states, dual-head LSTM, K-step rollout, MITRE mapping, SHAP:**

<p align="center">
<img src="assets/architecture_diagram.png" width="100%" alt="SentinelNet full architecture diagram"/>
</p>

**Leave-day-out cross-validation, including the leakage-proof that disqualified the stratified split:**

<p align="center">
<img src="assets/leave_day_out_baseline.png" width="90%" alt="Leave-day-out cross-validation and leakage findings"/>
</p>

> 📌 Add live dashboard screenshots to `assets/` (e.g. `assets/dashboard_upload.png`, `assets/dashboard_results.png`) and reference them here as the React UI is finalized — judges respond well to seeing the actual product, not just the pipeline diagram.

---

## 🛠️ Tech Stack

<table>
<tr><th>Layer</th><th>Technology</th><th>Purpose</th></tr>
<tr><td>⚙️ Backend</td><td>FastAPI · Uvicorn</td><td><code>/api/analyze</code>, <code>/api/health</code>, serves the built frontend as static files</td></tr>
<tr><td>🧠 Model</td><td>PyTorch · 2-layer LSTM (dual-head)</td><td>Temporal world model — next-state + infiltration prediction</td></tr>
<tr><td>📊 Preprocessing</td><td>Pandas · NumPy · Scikit-learn (StandardScaler)</td><td>Cleaning, windowing, feature scaling</td></tr>
<tr><td>🔍 Explainability</td><td>SHAP (GradientExplainer) + custom permutation fallback</td><td>Per-feature attribution for every score</td></tr>
<tr><td>🗺️ Stage Mapping</td><td>Nearest-centroid (Euclidean distance)</td><td>Maps forecasts to MITRE ATT&CK stages</td></tr>
<tr><td>📈 Baseline</td><td>Logistic Regression (Scikit-learn)</td><td>Honest comparison + leave-day-out generalisation stress test</td></tr>
<tr><td>🖥️ Frontend</td><td>React · Vite</td><td>Upload flow, risk timeline, stage view, feature/flow tables</td></tr>
<tr><td>🖥️ Alt. Frontend</td><td>Streamlit</td><td>No-build-step demo dashboard</td></tr>
<tr><td>💾 Dataset</td><td>CSE-CIC-IDS2018 (cleaned mirror)</td><td>Real, multi-day, multi-attack-family network traffic</td></tr>
<tr><td>🧪 Testing</td><td>Pytest · Oxlint</td><td>Preprocessing correctness, frontend lint/build checks</td></tr>
</table>

---

## 🗺️ Roadmap

Straight from the repo's own reproducibility notes — the next iteration should:

- [ ] Use **real timestamp-based windows** instead of 200-row pseudo-windows
- [ ] **Retrain with a populated destination-port feature** (currently always zero)
- [ ] **Separate infiltration from the generic any-attack target** for a dedicated infiltration signal
- [ ] Strengthen the **time-based evaluation split** so every attack family is represented appropriately in test data
- [ ] Ship each of the above with a **new matched checkpoint, scaler, and export bundle** — never mix artifacts across runs
- [ ] Add live dashboard screenshots and a richer SOC-facing UI walkthrough to this README

---

## 👥 Team

Built for **Smart India Hackathon 2026**, Problem Statement **SIH26153** (National Technical Research Organisation — Software).

[![GitHub](https://img.shields.io/badge/GitHub-sentinel--net-181717?style=for-the-badge&logo=github)](https://github.com/manansheth296-tech/sentinel-net)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Prachi%20Yadav-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/prachi-yadav-60466b343)

> 📌 Add each teammate's name, role, and profile link here so the judging panel can see full ownership of the project — e.g. *Model & ML Pipeline*, *Backend/API*, *Frontend/Dashboard*, *Data & Evaluation*.

---

## 📄 License

No license file is currently included in this repository. Add a `LICENSE` before distributing the project outside the team or organisation — MIT is a common, permissive default for hackathon projects if the team wants to open it up.

---

<div align="center">

*SentinelNet — forecasting the next move, not just flagging the last one.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=2,11,20&height=100&section=footer" width="100%"/>

**If this project was useful to you, please consider giving it a ⭐**

</div>

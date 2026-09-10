# SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
### 6-Person Team Execution Plan · NTRO · Sept 1 – Sept 20, 2026 (19-Day Build Sprint)

---

## 0. Executive Summary & Problem Context

**Core Objective (NTRO Problem Statement):**  
Build a predictive **world model** that models network dynamics ($P(S_{t+1} \mid S_t)$) across multi-step ($K$-step) rollouts to forecast multi-stage cyber attacks before completion, rather than a reactive point-in-time classifier.

### Key Deliverables & System Outputs
1. **Infiltration-Probability Timeline:** Multi-step forward horizon risk trajectory.
2. **Predicted MITRE ATT&CK Stage:** Progression tracking (`Reconnaissance` $\to$ `Initial Access` $\to$ `Lateral Movement` $\to$ `Command & Control` $\to$ `Exfiltration`).
3. **Explainability Engine:** SHAP / feature importance attributing risk to specific flags, ports, and flow statistics.
4. **Baseline Benchmark:** Performance evaluation vs. `LogisticRegression` baseline ($F_1$, Precision, Recall, False Positive Rate).
5. **Offline Demo Interface:** Interactive Streamlit web application running with zero internet/cloud dependencies.
6. **Submission Package:** Git repository, clean setup documentation (`README.md`), 2-page Architecture Document, 2-minute demo video, and 5-slide technical pitch deck.

> [!IMPORTANT]
> **Strict Offline Constraint:** The shipped demo and inference engine must execute **100% locally with zero cloud API dependencies**. Local helper models or rule engines may be used, but no runtime external API calls (e.g., cloud LLMs) are permitted.

---

### Team Roles & Skill Matrix

| Member | Semester | Stated Stack / Strengths | Assigned Primary Role |
|---|:---:|---|---|
| **Manan** | 5 | Python, C, Java | **Backend & Inference Engine Lead** |
| **Prachi Yadav** | 5 | Python, AI Frameworks, ML/DL, RAG, LLM Fine-tuning | **AI World Model Lead** |
| **Dia Patel** | 5 | Gen AI, UI/UX, Communications | **Frontend UI/UX & Pitch/Media Lead** |
| **Briyona Sanghvi** | 7 | Python, Streamlit, C, Java, AI Integrations, APIs | **Frontend Architecture & API Wiring Lead** |
| **Arya** | 7 | Web Dev, Python, AI/ML, Integration Testing | **Data Pipeline & Architecture Docs Lead** |
| **Parth Lalwani** | 7 | Python, Rapid Prototyping, Module Integration | **Data Engineering & Integration Testing** |

---

## 1. Locked Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Language** | Python 3.11 | Unified standard across model, backend, and UI. |
| **Dataset** | **CIC-IDS-2018** (CSV via CICFlowMeter) | Pre-labeled flow data with standard packet-level statistics. (CTU-13 reserved as stretch backup). |
| **Feature Extraction** | `pandas`, `scikit-learn` | Standard flow features (IAT distributions, packet counts/lengths, TCP flags, throughput). |
| **World Model** | PyTorch (**LSTM core architecture**) | Reliable convergence for sequence dynamics $P(S_{t+1} \mid S_t)$. (Transformer/GNN as stretch goals). |
| **Baseline Model** | `scikit-learn` (`LogisticRegression`) | Problem Statement benchmark requirement. |
| **Explainability** | `shap` (`TreeExplainer` / `KernelExplainer`) | Fast local attribution; Permutation Importance as fallback. |
| **Stage Mapping** | Rule-based lookup table | Deterministic mapping: Dataset labels $\to$ MITRE ATT&CK stages. |
| **Backend Engine** | Modular Python package (`backend/engine.py`) | Direct in-memory import for Streamlit; zero REST overhead. |
| **Frontend UI** | Streamlit | Rapid local reactive UI with native charting support. |
| **Version Control** | Git + GitHub (`main` trunk-based workflow) | Transparent commit history across all team members. |
| **Environment** | `venv` + `requirements.txt` | Standardized, clean local replication. |

> [!WARNING]
> **Out of Scope (Do Not Add):** Docker, Kubernetes, microservices, databases, user auth/login systems, mobile apps, or cloud LLM runtime calls.

---

## 2. System Contract & Architecture

### 2.1 Feature Schema (`docs/CONTRACT.md`)
- **Flow Aggregation:** Window-based sequences (30–60s bins or sequential flow timesteps per host IP).
- **Core Features:** Flow duration, packet count/lengths (Fwd/Bwd), IAT statistics (Mean/Std/Max), TCP flag distributions, Byte rates.
- **Normalization:** `StandardScaler` fitted strictly on training splits.

### 2.2 Model I/O JSON Contract
The backend inference engine (`backend/engine.py`) outputs this standard JSON schema:

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
    "world_model":       { "f1": 0.0, "precision": 0.0, "recall": 0.0, "fpr": 0.0 },
    "logistic_baseline": { "f1": 0.0, "precision": 0.0, "recall": 0.0, "fpr": 0.0 }
  }
}
```

### 2.3 Module Ownership Boundaries

```
SIH26153 Architecture
├── data/ & docs/               ──> Arya & Parth (Preprocessing, Splits, Documentation)
├── model/                      ──> Prachi Yadav (LSTM Dynamics, Tensors, Weights)
├── backend/                    ──> Manan (Inference Engine, Benchmark, MITRE Map)
└── app/                        ──> Dia & Briyona (Streamlit UI, Visualization, Media)
```

| Module / Scope | Lead Owner | Shared / Secondary | Responsibilities & Boundaries |
|---|---|---|---|
| **Backend Engine** | Manan | — | `backend/engine.py`, `backend/mitre_mapping.py`, benchmark harness, dependency packaging. |
| **World Model** | Prachi | — | `model/`, tensor pipelines, LSTM dynamics training, $K$-step rollout, model checkpointing. |
| **Frontend UI** | Dia & Briyona | — | `app/streamlit_app.py`, interactive plots, mock integration, error handling, visual polish. |
| **Data & Docs** | Arya & Parth | All | `data/download.py`, normalization scripts, `README.md`, `architecture.md`, test suites. |

---

## 3. Engineering & Git Workflow

- **Trunk-Based Commits:** Push small, atomic commits directly to `main` with semantic tags:
  - `feat(scope): ...`, `fix(scope): ...`, `docs(scope): ...`, `test(scope): ...`
- **Clean Sync:** Always run `git pull --rebase` before pushing; avoid forced pushes.
- **Repository Hygiene (`.gitignore`):** Ignore virtual environments (`venv/`), Python cache (`__pycache__/`), large dataset files (`*.csv`), and oversized weight files.
- **Contribution Tracking:** Ensure all 6 members have verified commits logged via `git shortlog -sn`.

---

## 4. 19-Day Sprint Roadmap (Sept 1 – Sept 20)

### Phase 1: Foundation & Contracts (Days 0–2 · Sept 1–3)
- **Day 0 (Kickoff):** Repo structure setup (`data/`, `model/`, `backend/`, `app/`, `docs/`), raw dataset acquisition (`data/download.py`), `requirements.txt` v1.
- **Days 1–2 (Contract Freeze):** 
  - Standardize feature schema in `docs/CONTRACT.md`.
  - Backend creates `backend/engine.py` with mock JSON matching §2.2.
  - Frontend wires Streamlit against mock contract to create a fully navigable UI.
- **Checkpoint (Day 2 EOD):** End-to-end interactive UI functional using mock data.

### Phase 2: Core Model & Baseline (Days 3–7 · Sept 4–7)
- **Model:** Train initial LSTM on flow sequences for dynamics learning $P(S_{t+1} \mid S_t)$ and probability estimation.
- **Backend:** Build `LogisticRegression` baseline and automated benchmark suite ($F_1$, Precision, Recall, FPR).
- **Data & Mapping:** Construct `backend/mitre_mapping.py` rules and integration tests.
- **UI:** Integrate dynamic timeline charts, flagged flow table, and feature importance panels.
- **Checkpoint (Day 7 EOD):** Real predictions generated by LSTM on test splits; baseline benchmark numbers established.

### Phase 3: Forecasting, Explainability & Integration (Days 8–13 · Sept 8–14)
- **Days 8–10 (Rollout & SHAP):**
  - Implement multi-step forward horizon rollout ($K$-step forecasting).
  - Integrate SHAP / feature attribution into `top_features` contract output.
  - Validate MITRE mapping against multiple attack vectors (DoS, PortScan, Brute Force, Botnet, Infiltration).
- **Days 11–13 (System Wiring):**
  - Finalize unified inference entry point: `run_inference(file_path) -> dict`.
  - Wire Streamlit to real engine; implement robust error handling (e.g., malformed or empty files).
  - Perform end-to-end offline integration runs.
- **Checkpoint (Day 13 EOD):** Complete demo-critical path working fully offline on a clean test environment.

### Phase 4: Polish, Documentation & Submission (Days 14–19 · Sept 15–20)
- **Days 14–15 (Docs & Hardening):** Write comprehensive `README.md`, 2-page Architecture Document, and address edge cases.
- **Day 16 (Sept 17):** **Feature Freeze** — zero new features; bug fixes and stability only.
- **Day 17 (Sept 18):** Record 2-minute demo video; design 5-slide technical pitch deck.
- **Day 18 (Sept 19):** Clean-clone verification on fresh environment; pitch rehearsal.
- **Day 19 (Sept 20):** Final review and early project submission.

---

## 5. Demo-Critical Path & Fallback Plan

### Non-Negotiable Flow (Target: Day 13)
```
[Upload CSV Sample] 
   └──> [Feature Extraction & Windowing]
         └──> [LSTM Forward Rollout: P(S_t+1 | S_t)]
               ├──> [Infiltration Timeline Chart]
               ├──> [Predicted MITRE Stage Badge]
               ├──> [SHAP Feature Importance Panel]
               └──> [Benchmark Comparison Table (Model vs Logistic Baseline)]
```

### Prioritized Cut List (In Case of Time Constraints)
1. **Model Architecture:** Stick strictly to LSTM; drop Transformer/GNN explorations.
2. **PCAP Parsing:** Use pre-computed CICFlowMeter tabular features; omit raw Scapy PCAP parsing.
3. **Explainability:** Fall back from SHAP to Permutation Importance or Logistic Regression weights.
4. **Horizon Rollout:** Reduce multi-step $K$-horizon visualization to single-step forward forecast.
5. **UI Complexity:** Retain a clean single-page Streamlit dashboard; avoid multi-page routing.
6. **Backend Layer:** Keep `backend/engine.py` as an imported module; avoid FastAPI REST wrappers.

---

## 6. Demo Video Breakdown (2:00 Max)

| Time Window | Focus Area | Visual & Script Narrative |
|:---:|---|---|
| **0:00 – 0:15** | **Problem Statement** | "SentinelNet: AI-based network attack forecasting via state dynamics ($P(S_{t+1} \mid S_t)$)." |
| **0:15 – 0:40** | **Input & Pipeline** | Upload CIC-IDS-2018 sample traffic CSV $\to$ automated local feature processing. |
| **0:40 – 1:10** | **Forecast & MITRE Stage** | Dynamic probability escalation curve $\to$ progression into Lateral Movement/C2. |
| **1:10 – 1:35** | **Explainability** | SHAP feature breakdown: SYN flag bursts, anomalous forward IAT distributions. |
| **1:35 – 1:55** | **Benchmark Validation** | Comparative performance metrics proving superiority over logistic baseline. |
| **1:55 – 2:00** | **Conclusion** | Summary card with Team ID (SIH26153), NTRO problem statement, and repository link. |

---

## 7. Risk Management Register

| Risk | Impact | Mitigation Strategy |
|---|:---:|---|
| **Slow Model Training on Local Machines** | High | Subsample representative slices of CIC-IDS-2018 (e.g., single-day captures); optimize batch sizing. |
| **SHAP Computation Latency** | Med | Utilize background subsamples (50–100 samples) for `KernelExplainer` or use Tree/Permutation methods. |
| **Deep Model Underperforms Baseline** | Med | Document results transparently with objective diagnostic analysis (e.g., sequence length, dataset size constraints). |
| **Accidental Cloud API Leakage** | Critical | Conduct mandatory offline validation tests (Wi-Fi/Network disabled) prior to feature freeze. |
| **Data Schema Mismatches** | High | Strictly freeze `docs/CONTRACT.md` schema on Day 1; enforce schema unit tests. |
| **Junior Team Members Blocked** | Med | Pair programming sessions (e.g., Prachi + Manan on evaluation harness) and daily status syncs. |
| **UI Rendering Errors During Demo** | High | Package pre-validated sample test files (`data/samples/`) guaranteed to run error-free. |

---

## 8. Role-Specific Implementation Directives

- **Manan (Backend & Inference):** Focus on core execution logic (`backend/engine.py`), baseline training harness, MITRE stage mapping, and package reproducibility. Keep backend in-process (avoid unnecessary web server boilerplate).
- **Prachi Yadav (AI World Model):** Prioritize the sequence dynamics model ($P(S_{t+1} \mid S_t)$) and rollout mechanism. Keep training pipelines isolated from UI code.
- **Dia Patel (Frontend & Media):** Drive UI aesthetic polish, responsive layouts, presentation slide design, and video production narration.
- **Briyona Sanghvi (Frontend & API Wiring):** Lead Streamlit-to-backend data wiring, state management, and defensive error handling for file uploads.
- **Arya & Parth (Data Engineering & Integration):** Manage data ingestion, feature normalization, integration test suites, `README.md` documentation, and the final 2-page Architecture Document.

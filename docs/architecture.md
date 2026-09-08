# SentinelNet Technical Architecture Document
### AI-Based Network Attack Forecasting System (SIH26153 · NTRO)

---

## 1. System Architecture & End-to-End Dataflow

SentinelNet is structured as a modular, 4-tier pipeline operating 100% offline:

```
[ CIC-IDS-2018 CSV / Real-Time Flows ]
                  │
                  ▼
┌────────────────────────────────────────────────────────┐
│  Tier 1: Data Ingestion & Preprocessing (data/)        │
│  - Column renaming & V4 schema harmonization           │
│  - NaN / Inf sanitization & header deduplication       │
│  - Feature extraction: 77 raw numeric flow features    │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│  Tier 2: Temporal State Aggregation (backend/data_prep)│
│  - Flow aggregation: Mean(77) + Std(77)                │
│  - Metadata enrichment: Unique Dst Ports + Flow Count  │
│  - Output: 156-dim State Vector S_t per time window    │
│  - Sequence Stacking: 20 consecutive windows (20, 156) │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│  Tier 3: AI World Model & Analytics (model/ & backend/)│
│  - Pre-fitted StandardScaler (scaler_v4.pkl)           │
│  - Multi-layer PyTorch LSTM: P(S_t+1 | S_t) dynamics   │
│  - K-step forward rollout & probability trajectory     │
│  - MITRE ATT&CK stage classification                   │
│  - Local SHAP / Feature importance engine              │
│  - Logistic Regression comparative baseline            │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│  Tier 4: Offline Visualization Dashboard (app/)        │
│  - Real-time infiltration timeline curve               │
│  - MITRE ATT&CK Kill Chain status indicator            │
│  - Flagged high-risk flows table                       │
│  - XAI Feature attribution bar plots                   │
│  - Baseline vs. World Model benchmark comparison       │
└────────────────────────────────────────────────────────┘
```

---

## 2. Temporal State Vector Formulation

To model system dynamics over continuous network traffic without losing micro-burst characteristics:

1. **Raw Feature Subspace ($\mathbf{f} \in \mathbb{R}^{77}$):**
   Excludes all target and ID fields (`Label`, `Timestamp`, `Src IP`, `Dst IP`, `Flow ID`, `Src Port`, `Dst Port`) to strictly eliminate data leakage.
2. **Window Statistical Aggregation ($\mathbf{S}_t \in \mathbb{R}^{156}$):**
   $$\mathbf{S}_t = \Big[ \boldsymbol{\mu}(\mathbf{f}_t),\, \boldsymbol{\sigma}(\mathbf{f}_t),\, \text{UniqueDstPorts}_t,\, \text{FlowCount}_t \Big]$$
   Where $\boldsymbol{\mu}(\mathbf{f}_t) \in \mathbb{R}^{77}$ and $\boldsymbol{\sigma}(\mathbf{f}_t) \in \mathbb{R}^{77}$.
3. **Temporal Sequence Tensor ($\mathbf{X} \in \mathbb{R}^{B \times 20 \times 156}$):**
   Constructed from a sliding window of 20 consecutive discrete state vectors representing network evolution across time.

---

## 3. World Model Dynamics & Inference

- **State Transition Function:**  
  The world model parameterizes the conditional state transition probability distribution:
  $$P(\mathbf{S}_{t+1} \mid \mathbf{S}_t, \mathbf{S}_{t-1}, \dots, \mathbf{S}_{t-T+1})$$
- **Multi-Step Rollout ($K$-Horizon):**  
  The model performs autoregressive simulation forward in time to project attack probability escalation before attack stages complete.
- **MITRE ATT&CK Mapping:**  
  Deterministic mapping translates predicted attack categories into standardized cyber kill chain phases:
  - `Reconnaissance` (PortScan, Vulnerability Scanning)
  - `Initial Access` (Brute Force, SSH/FTP Infiltration)
  - `Lateral Movement` (Internal Spreading, Botnet Infiltration)
  - `Command & Control` (C2 Beaconing, Heartbeats)
  - `Exfiltration` (Anomalous Outbound Volume Spikes)

---

## 4. Benchmark & Validation Protocol

- **Validation Splits:** Evaluated using strict chronological splits and cross-file out-of-distribution captures (no random shuffling).
- **Comparison Baseline:** Scikit-learn `LogisticRegression` trained on the exact same feature distribution.
- **Evaluation Metrics:**
  $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

# SentinelNet ➺  LSTM World Model (Final Dhoogla Checkpoint)

**Owner:** Prachi (AI & Models) · **Status:** Final for internal hackathon demo · **PS:** SIH26153

This is the single source of truth for what the model is, how it was trained, what its
numbers actually mean, and how to wire it into the backend. Read this before asking
"why does X do Y" ➺  it's probably answered here.

---

## 1. What this model actually does

A dual-head, 2-layer LSTM that treats network traffic as a **world model**, not a
per-flow classifier. Instead of labeling individual flows, it learns how the
*network's overall state* evolves over time, so it can:

1. Represent recent traffic as a sequence of state vectors.
2. Predict the **next** state (state-transition modeling ➺  the actual "world model" part).
3. Predict the **probability of attack** in that next state.
4. Roll that forward autoregressively for a **K-step future forecast**.
5. Map the predicted state to a **MITRE ATT&CK stage**.
6. Explain the prediction with **SHAP** (or a permutation-importance fallback).

This directly satisfies the SIH26153 ask: *"learn state-transition dynamics... forecast
future network states... map predicted behaviour to recognised attack stages... provide
explainability."*

---

## 2. Files to push ➺  and which ones NOT to

| File | Push? | Why |
|---|---|---|
| `world_model_v4_best.pt` | ✅ Yes | Trained LSTM checkpoint (best val F1) |
| `scaler_v4.pkl` | ✅ Yes | The StandardScaler fit on THIS run's train split. `backend/data_prep.py` hardcodes this exact filename. |
| `export_bundle_v4.json` | ✅ Yes | Single source of truth for `feature_cols`, `seq_len`, `input_dim`, windowing mode. Everything else derives from this file at import time. |
| `scaler.pkl` | ❌ No | Leftover from an earlier run in the same folder. Stale. Delete it or move it out so nobody grabs it by mistake. |

All three files must come from **the same training run** (i.e. all written in the same
execution of Cell 14). Never mix a checkpoint from one run with a scaler from another ➺ 
the feature scaling won't match what the model was trained on, and predictions will be
silently wrong (no crash, just garbage).

**Where they go:** `model/world_model_v4_best.pt`, `model/scaler_v4.pkl`,
`model/export_bundle_v4.json` in the backend project root.

---

## 3. Architecture

```
                 156-dim state Sₜ
                       │
     ┌─────────────────────────────────┐
     │   20 consecutive states          │
     │   Sₜ₋₁₉ ... Sₜ  →  20 × 156       │
     └─────────────────┬─────────────────┘
                        ▼
                 LSTM Layer 1 (128 hidden)
                        ▼
                 LSTM Layer 2 (128 hidden)
                        ▼
                    LayerNorm
                        ▼
              128-D representation
               /                \
              ▼                  ▼
        STATE HEAD          ATTACK HEAD
     Linear→ReLU→Dropout   Linear→ReLU→Dropout
     Linear(128→156)       Linear(64→1)
              │                  │
              ▼                  ▼
       Predicted Sₜ₊₁        Sigmoid → P(attack)
```

- **Params:** ~323,741 trainable
- **Dropout:** 0.3
- **Why two heads:** SIH asks for state-transition *learning*, not just classification.
  The state head learns `P(Sₜ₊₁ | Sₜ)`; the attack head estimates maliciousness of that
  predicted next state. Together they enable genuine multi-step forward rollout, not
  just "classify what I already see."
- **Why LSTM (not Transformer/GNN):** the problem is fundamentally temporal ➺  a single
  flow rarely reveals an infiltration, but the *progression* across states does. LSTM is
  lightweight enough to train and iterate on inside a hackathon timeline, and the PS
  explicitly permits LSTM as a valid sequence model.

---

## 4. Data & feature schema

- **Dataset:** `dhoogla/csecicids2018` (Kaggle) ➺  a cleaned mirror of CSE-CIC-IDS2018,
  10 files, one attack family per day (Bruteforce, DoS ×2, DDoS ×2, Web ×2, Infiltration
  ×2, Botnet).
- **Raw features:** 77 numeric CICFlowMeter flow features (packet counts, byte counts,
  IAT statistics, flag counts, active/idle timing, etc.)
- **State vector construction:** per 200-row window → `mean` + `std` for each of the 77
  raw features (154 values) + `unique_dst_ports` + `flow_count` = **156-dim state**.
- **Windowing:** `WINDOW_ROWS = 200` ➺  a **pseudo-window** (200 flow records), *not* a
  real 10-second time window, because this dataset mirror has no usable Timestamp
  column. `export_bundle_v4.json` sets `"using_real_time_windows": false` to make this
  explicit to anything reading the bundle.
- **Sequence length:** `SEQ_LEN = 20` consecutive states → `(20, 156)` LSTM input.
- **Label:** `is_attack` = 1 if ANY flow in the window is non-Benign, else 0. **This is a
  generic "any attack" label, not infiltration-specific** ➺  see §7 caveats.
- **⚠️ Known landmine ➺  `unique_dst_ports`:** this dataset mirror has no destination-port
  column, so this feature is **always 0** for every window in training. The model has
  never seen it be anything else. If a downstream pipeline (e.g. Parth's real
  `data_prep.py`) computes a genuine non-zero port count from real traffic, the scaler
  will treat it as a wild outlier. **Force this feature to 0 at inference time** to match
  training distribution until a retrain properly incorporates it.

---

## 5. Training setup

| Setting | Value |
|---|---|
| Split | 70% / 15% / 15%, computed **within each file** (chronological, not random) |
| Clipping | 0.1st/99.9th percentile, bounds fit on train only |
| Scaling | `StandardScaler`, fit on train only |
| Loss | `MSE(pred_state, next_state) + BCEWithLogits(pred_logit, label)`, λ=1.0 |
| Class imbalance | `pos_weight = n_neg/n_pos` in BCE (~1.66 on this run) |
| Optimizer | Adam, lr=1e-3, weight_decay=1e-5 |
| Scheduler | ReduceLROnPlateau on val loss |
| Early stopping | patience=6 on val F1 |
| Epochs run | up to 30 (stopped early once val F1 plateaued) |

---

## 6. Results ➺  the honest numbers

```
=== TEST SET RESULTS ===
F1:        0.8354
Precision: 0.9278
Recall:    0.7597
FPR:       0.0172
Confusion matrix -> TN=3654  FP=64  FN=260  TP=822
```

**Say this, not "93% accurate" or any other rounded/misremembered version:**
> "83.5% F1, 92.8% precision, 76.0% recall, 1.7% false-positive rate on held-out test
> data ➺  precision is high because we prioritize few false alarms, at some cost to
> recall."

### Two caveats to state proactively, not hide

1. **Per-file test-set imbalance.** 6 of the 10 files (Bruteforce, DoS1, DDoS1, Web1,
   Web2, Botnet) have **zero attack windows in their test slice** ➺  the chronological
   per-file split means the attack traffic in those files fell entirely into train/val.
   The headline F1 is real, but it's driven mainly by the 4 files that do have attacks
   at test time (DoS2, DDoS2, Infil1, Infil2). Framing for the viva: *"we found a
   time-based per-file split can starve some files' test slices of examples ➺  noting
   this as a methodology improvement for the next iteration."*
2. **Infiltration-specific weakness.** The per-file breakdown shows the actual
   Infiltration-day file (`Infil1`) scores much lower (**F1 ≈ 0.21**) than the aggregate
   number. The label being trained on is generic "any attack," not
   infiltration-specific ➺  a real gap relative to the PS's headline ask. Framing: *"this
   is v1 with a generic attack label; infiltration-specific target definition is
   next-step work."*

---

## 7. MITRE ATT&CK stage mapping

Because this dataset mirror strips per-row attack-type labels (one attack family per
whole file), stage is inferred **from the filename**, not from the row itself:

| Filename contains | Stage |
|---|---|
| bruteforce | Credential Access / Initial Access |
| dos / ddos | Impact |
| web | Initial Access |
| infil | Lateral Movement |
| botnet | Command & Control |
| (not attack) | Benign |

**Be upfront that this is a file-level heuristic, not a per-row model-derived stage** ➺ 
it's a reasonable simplification for this dataset mirror, but it's not the same as
inferring stage from the traffic pattern itself.

`current_stage` in the demo output is a **majority vote across the last 5 windows**
(not a single window) ➺  a single last window can be a fluke (captures often end with a
few quiet seconds right after the attack script finishes), which earlier made a 95%+
malicious file misleadingly show "Benign." The JSON also returns
`current_stage_recent_window_votes` so you can show the actual vote breakdown live if
a judge asks.

---

## 8. Explainability

- **Primary:** SHAP (`DeepExplainer` / `GradientExplainer` depending on environment),
  installed via `pip install shap`.
- **Fallback:** a custom `_permutation_importance()` that averages multiple random
  shuffles per feature (not just one) ➺  a single shuffle can land near-zero by chance,
  especially on a confident prediction, so this is more stable for demo purposes.
- Returns top-3 contributing features with their contribution scores.

---

## 9. Inference contract (`predict_demo()`)

```python
predict_demo(file_path: str, k_steps: int = 5) -> dict
```

Returns JSON matching `CONTRACT.md`:

```json
{
  "infiltration_timeline": [
    {"step_ahead": 1, "infiltration_prob": 0.9972, "predicted_stage": "Impact"},
    ...
  ],
  "current_stage": "Impact",
  "current_stage_recent_window_votes": {"Impact": 4, "Benign": 1},
  "top_features": [
    {"feature": "Fwd Seg Size Min_mean", "contribution": 0.0496}
  ],
  "benchmark": {"world_model_f1": 0.8354}
}
```

No frontend or backend contract changes needed ➺  this matches the shape Dia and Manan
have already been building against.

---

## 10. Backend integration notes (for Manan)

1. Copy the 3 files from §2 into `model/`, overwriting anything left there from
   earlier experiments.
2. `backend/data_prep.py` reads everything (`FEATURE_COLS`, `RAW_FEATURE_NAMES`,
   `INPUT_DIM`, `SEQ_LEN`, windowing mode) directly from `export_bundle_v4.json` at
   import time ➺  you don't need to hardcode anything, it syncs automatically.
3. **Force `unique_dst_ports = 0`** in the cleaned feature output before scaling (see
   §4 landmine) ➺  this model was never trained on real port-count values.
4. `using_real_time_windows` in the bundle is `false` ➺  the pipeline should fall back to
   200-row pseudo-windows, not real 10-second timestamp windows, for this checkpoint.
5. Column **order** matters for `scaler.transform()`, not just names/count.
   `RAW_FEATURE_NAMES` is derived in-order from `FEATURE_COLS`, so as long as
   `clean_dataset.py` outputs columns via `RAW_FEATURE_NAMES` (which it does), order is
   guaranteed to match ➺  no manual reordering needed.

---

## 11. Future work (say this proactively if asked "is this final?")

- Replace 200-row pseudo-windows with real 10-second timestamp-based windows.
- Retrain with `unique_dst_ports` properly populated from real port data.
- Separate "infiltration" as its own target from generic "any attack."
- Fix the chronological per-file train/val/test split so no file's test slice can end
  up with zero attack examples (block-interleaved splitting, scattered assignment).
- Optional stretch: zero-shot generalization test (train without one attack family,
  test only on it) ➺  scaffolded in the notebook but not yet run.

---

**Bottom line for the demo:** this is a real, previously-validated, line-by-line
reviewed checkpoint. Report the actual numbers (§6), state the two caveats
proactively (§6), and you're in a strong, honest position for the viva.

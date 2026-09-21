# model/ vs model2/ — Audit and Decision

The repository ships two model directories. They are **not** duplicates —
they contain different checkpoint weights and materially different code.

## What was compared

| | `model/` | `model2/` |
|---|---|---|
| `export_bundle_v4.json` status field | `"PROTOTYPE — will be retrained once team finalizes cleaned dataset"` | `"FINAL — dhoogla, submission version"` |
| Recorded F1 / Precision / Recall / FPR | 0.8403 / 0.9304 / 0.7662 / 0.0167 | 0.8354 / 0.9278 / 0.7597 / 0.0172 |
| `world_model_v4_best.pt` (md5) | `ced996c...` | `9d7e2ca...` (different weights) |
| `scaler_v4.pkl` (md5) | identical to model2's | identical to model's |
| SHAP / explainability code | none | `shap.GradientExplainer` wrapped around the risk head, with a documented permutation-importance fallback |
| MITRE staging for forecasted states | not implemented | nearest-centroid matching against `stage_centroids` baked into the bundle |
| `unique_dst_ports` handling | not explicitly discussed | explicitly documented and forced to 0.0 to match the training distribution (`_ALWAYS_ZERO_PORT_FEATURE`) |
| Checkpoint/scaler path portability | Google Drive path in bundle metadata (metadata only, not used at runtime) | same, but directory name documents this is the actual submission checkpoint |

## Decision

**`model2/` is the canonical implementation.** `backend/engine.py` imports
model2's `inference.py` and `preprocessing.py` exclusively. `model/` is left
in the repository, untouched, for reference/comparison — nothing in the new
backend, API, or frontend reads from it.

## Consequence for previously-reported numbers

`backend/engine.py` used to hardcode `f1=0.8403` etc. — those are `model/`'s
numbers, not `model2`'s, and they were duplicated as a literal in Python
source rather than read from a bundle. Both problems are fixed: the
benchmark numbers now come from `model2/export_bundle_v4.json` at import
time, so they cannot drift from the canonical checkpoint's own recorded
values.

## What remains genuinely unresolved

- Neither bundle ships the original *training* background distribution
  needed for a textbook SHAP background set. `backend/explain.py` documents
  and works around this (see its module docstring) using other windows
  from the same uploaded session; this is a legitimate but non-default
  choice worth knowing about if these SHAP numbers are compared against a
  future retrain that does ship a background set.
- The logistic-regression baseline in `backend/train_baseline.py` can be run
  against the bundled sample CSVs in `data/samples/` without any additional
  data. Run:
  ```
  python backend/train_baseline.py --output-json backend/baseline_result.json
  ```
  The script defaults to `data/samples/` and prefers files whose names start
  with `sample_` (which contain labeled attack traffic). The result is a
  **small-sample estimate** (3 files × 5% rows) — not a full CIC-IDS-2018
  evaluation. The frontend clearly labels it as such. For a rigorous
  comparison, pass the full dataset via `--data-dir` or `SENTINELNET_RAW_DATA_DIR`.

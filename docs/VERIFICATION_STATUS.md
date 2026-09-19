# Verification status — read this before trusting "it works"

This document exists because the task this repository was built for explicitly
forbids fabricated results, including fabricated *test* results. Here is
exactly what was and wasn't run, and why.

## Environment this was built in

The sandbox used to write this code had `numpy`, `pandas`, `scipy`,
`scikit-learn`, and `joblib` installed, but **no `torch`, `shap`, or
`fastapi`, and no network access to install them**. That environment cannot
load `world_model_v4_best.pt`, run the LSTM, run SHAP, or start the FastAPI
app.

## What was actually executed and passed

- `python3 -m py_compile` on every modified/new Python file
  (`backend/engine.py`, `backend/explain.py`, `backend/api.py`,
  `backend/train_baseline.py`, `tests/test_explain.py`, `tests/test_api.py`,
  `app/streamlit_app.py`, plus the untouched `model/` and `model2/` modules)
  — confirms no syntax errors.
- `node --check` on `frontend/app.js` and `frontend/config.js` — confirms
  no JavaScript syntax errors.
- **`tests/test_data_prep.py`, the pre-existing 39-test suite, was run with
  `python -m unittest` and every test passed.** This suite doesn't depend on
  torch, so it could run in this sandbox as-is; it exercises
  `backend/data_prep.py`'s 77-feature schema, 156-dim state vector,
  leakage columns, chronology, scaler behavior, etc. — none of that code
  was modified.
- A byte-level audit of `model/` vs `model2/` (md5sums of both checkpoints
  and scalers, full `diff` of both `preprocessing.py`/`inference.py`
  pairs and both `export_bundle_v4.json` files) — this is how
  `docs/MODEL_DECISION.md`'s claims were established, not assumption.

## What was written correctly but NOT executed

- `backend/engine.py` end-to-end (needs torch + a real uploaded file)
- `backend/explain.py`'s SHAP path (needs torch + shap)
- `backend/api.py` (needs fastapi; `tests/test_api.py` needs `fastapi.testclient`)
- `tests/test_explain.py`'s SHAP-path test (skips itself if `shap` is absent —
  it will actually run in your environment since `shap` is in
  `requirements.txt`)
- The frontend was not opened in a real browser and clicked through; it was
  reviewed by hand against the API contract `backend/engine.py` returns, and
  checked for JS syntax errors only.

## What you should do to actually verify this

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
uvicorn backend.api:app --reload --port 8000
# separately: open frontend/index.html (or sentinelnet.html) and upload a
# real CIC-IDS-2018-style flow CSV.
```

If something breaks, it is a real bug to fix, not a known-and-hidden gap —
nothing here was deliberately left broken. But "written and reviewed
carefully" is a different, weaker claim than "ran and observed working end
to end," and this document exists so that distinction isn't lost.

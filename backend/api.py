"""
backend/api.py — SentinelNet API layer (FastAPI)
==================================================

Thin HTTP wrapper around backend/engine.py. This file does not implement
any inference/explainability logic itself — it validates uploads, calls
the existing backend, and returns its output unmodified (or an explicit
error) as JSON.

Run:
    uvicorn backend.api:app --reload --port 8000
    (from the project root, so `backend` is importable as a package)

Endpoints
---------
GET  /api/health            - liveness + whether the model is loaded
POST /api/analyze           - upload a CSV/Parquet capture, run full pipeline
GET  /api/model             - model/version/limitations metadata
GET  /api/mitre             - the rule-based MITRE stage lookup table
GET  /api/benchmark         - recorded + (if present) live baseline benchmark
"""

from __future__ import annotations

import os
import shutil
import tempfile
import traceback
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

from . import engine  # noqa: E402
from .mitre_mapping import MITRE_STAGE_MAP  # noqa: E402

app = FastAPI(
    title="SentinelNet API",
    description="Network attack-risk forecasting with SHAP explainability. Prototype/benchmark checkpoint — see /api/model for limitations.",
    version="1.0.0",
)

# Static frontend is a same-origin file:// or simple http.server page in dev;
# allow local dev origins broadly, restrict in real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_EXTENSIONS = {".csv", ".parquet"}
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


def _safe_suffix(filename: str) -> str:
    _, ext = os.path.splitext(filename or "")
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Supported: {sorted(ALLOWED_EXTENSIONS)}. "
                   "PCAP is not supported — this backend expects flow-record CSV/Parquet "
                   "(e.g. CICFlowMeter output), not raw packet captures.",
        )
    return ext


@app.get("/api/health")
def health():
    try:
        eng = engine.get_engine()
        model_loaded = "model" in eng
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "degraded", "model_loaded": False, "error": str(e)})
    return {"status": "ok", "model_loaded": model_loaded, "model_version": "SIH_LSTM_V4", "canonical_source": "model2/"}


@app.get("/api/model")
def model_info():
    return {
        "model_version": "SIH_LSTM_V4",
        "canonical_source": "model2/",
        "status": engine.MODEL_STATUS,
        "benchmark": {
            "world_model": engine.WORLD_MODEL_BENCHMARK,
            "source": engine.BENCHMARK_SOURCE,
        },
        "architecture": {
            "type": "2-layer LSTM world model, dual head",
            "hidden_size": 128,
            "num_layers": 2,
            "dropout": 0.3,
            "layer_norm": True,
            "heads": ["next-state prediction (156-d)", "attack-risk classification (1 logit)"],
        },
        "input_contract": {
            "raw_features": 77,
            "state_dim": 156,
            "sequence_length": 20,
            "window_rows": 200,
        },
        "limitations": engine.KNOWN_LIMITATIONS,
    }


@app.get("/api/mitre")
def mitre_table():
    return {
        "type": "rule-based lookup table, not a learned classifier",
        "source": "backend/mitre_mapping.py",
        "mapping": MITRE_STAGE_MAP,
    }


@app.get("/api/benchmark")
def benchmark():
    return {
        "world_model": engine.WORLD_MODEL_BENCHMARK,
        "world_model_source": engine.BENCHMARK_SOURCE,
        "logistic_baseline": engine._load_logistic_baseline(),
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    ext = _safe_suffix(file.filename)

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        result = engine.run_inference(tmp_path)

        if isinstance(result, dict) and result.get("error"):
            # Real pipeline error (bad schema, too few windows, etc.) —
            # surfaced as a 422 with the real message, never converted into
            # a fake successful analysis.
            return JSONResponse(status_code=422, content=result)

        return result
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis failed unexpectedly: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


FRONTEND_DIR = os.path.join(os.path.dirname(CURRENT_DIR), "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


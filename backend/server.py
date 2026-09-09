"""
backend/server.py — SentinelNet FastAPI REST API Server
=========================================================

Exposes the /api/analyze endpoint expected by the React + Vite frontend.
Handles CSV / PCAP file uploads, feeds them to backend/engine.py for
LSTM World-Model inference, SHAP explainability, and MITRE mapping.
"""

import os
import sys
import tempfile
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure repo root and backend are in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
for path in [PROJECT_ROOT, CURRENT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

from backend.engine import run_inference, predict_demo, BENCHMARK_METRICS

app = FastAPI(
    title="SentinelNet AI Network Attack Forecasting API",
    description="Offline sequence-dynamics LSTM world model API for multi-step network attack forecasting.",
    version="1.0.0"
)

# Enable CORS for local Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "service": "SentinelNet API",
        "status": "online",
        "model": "LSTM World Model V4",
        "benchmark": BENCHMARK_METRICS
    }


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "sentinelnet-backend"}


@app.post("/api/analyze")
async def analyze_endpoint(
    file: Optional[UploadFile] = File(None),
    k_steps: int = 5
):
    """
    Main analysis endpoint consumed by React frontend.
    Accepts CSV network traffic capture or uses default validated capture if file is omitted.
    """
    temp_file_path = None
    try:
        if file and file.filename:
            suffix = os.path.splitext(file.filename)[1] or ".csv"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                content = await file.read()
                tmp.write(content)
                temp_file_path = tmp.name
            
            result = run_inference(temp_file_path, k_steps=k_steps)
        else:
            result = predict_demo(k_steps=k_steps)
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

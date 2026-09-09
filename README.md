# SentinelNet

SentinelNet is a network-traffic analysis platform that combines a FastAPI inference service with a React/Vite dashboard. It transforms CICFlowMeter-style flow data into temporal network states, forecasts near-future attack risk with an LSTM world model, maps the result to a MITRE ATT&CK stage, and exposes feature-level explanations for the dashboard.

> **Project status:** internal prototype / hackathon demonstration. The current model is trained on a generic any-attack target, not an infiltration-only target. See [Model limitations](#model-limitations) before using the results operationally.

## Features

- Upload `.csv` or `.pcap` files from the web dashboard.
- Clean and normalize CICFlowMeter column names, repeated headers, missing values, and infinite values.
- Aggregate 77 raw numeric flow features into 156-dimensional temporal state vectors.
- Feed the latest 20 states into the V4 LSTM world model.
- Forecast multiple future risk probabilities.
- Display predicted MITRE ATT&CK stage, top feature contributions, flagged flows, and benchmark metrics.
- Run the backend independently through FastAPI and the frontend independently through Vite.

## Architecture

```text
Network capture / CICFlowMeter CSV
							|
							v
			 FastAPI /api/analyze
							|
							v
	 Column normalization and cleaning
							|
							v
	200-row windows -> mean/std + counts
							|
							v
			 20 x 156 LSTM sequence
							|
							v
	Risk forecast + stage + explanations
							|
							v
			 React/Vite dashboard
```

The model state is built as:

```text
77 raw features
	-> mean (77) + standard deviation (77)
	-> unique_dst_ports (1) + flow_count (1)
	-> 156-dimensional state
	-> 20 consecutive states
	-> LSTM input shape: (20, 156)
```

The current V4 bundle uses 200-row pseudo-windows because the training mirror does not provide a reliable timestamp. The preprocessing contract is defined in [docs/CONTRACT.md](docs/CONTRACT.md).

## Repository layout

```text
.
├── requirements.txt                # Python environment used by the backend
├── backend/
│   ├── __init__.py
│   ├── data_prep.py                # CSV cleaning and state construction
│   ├── engine.py                   # Cached model inference and response assembly
│   ├── explain.py                  # SHAP / permutation explanations
│   ├── mitre_mapping.py            # Stage mapping helpers
│   └── server.py                   # FastAPI application server (/api/analyze)
├── data/
│   ├── __init__.py
│   ├── clean_dataset.py            # Dataset cleaning utilities
│   ├── convert_to_v4.py            # Feature format converter
│   └── sample_test.csv             # Pre-validated sample capture
├── model/
│   ├── __init__.py
│   ├── inference.py                # V4 LSTM inference wrapper
│   ├── preprocessing.py            # Model-side preprocessing
│   ├── export_bundle_v4.json       # Feature order and model configuration
│   ├── scaler_v4.pkl               # 156-dim StandardScaler
│   ├── world_model_v4_best.pt      # V4 checkpoint
│   └── README_LSTM_WORLD_MODEL.md  # Model architecture & evaluation notes
├── app/
│   ├── __init__.py
│   └── streamlit_app.py            # Standalone Streamlit dashboard
├── frontend/
│   ├── src/                        # React dashboard
│   ├── public/                     # Static assets (icons, favicons)
│   ├── package.json                # Frontend scripts and dependencies
│   └── vite.config.js              # Port and backend API proxy
├── tests/test_data_prep.py         # Preprocessing test suite
└── docs/CONTRACT.md                # Data and response contract
```

## Requirements

- Python 3.11 or a compatible modern Python version.
- Node.js 18+ and npm.
- The Python dependencies in `requirements.txt`.
- The V4 model artifacts in `model/`.

The backend expects these files from the same training run:

```text
model/world_model_v4_best.pt
model/scaler_v4.pkl
model/export_bundle_v4.json
```

`scaler_v4.pkl` is required by `backend/engine.py` and must match the checkpoint and export bundle. Do not mix artifacts from different training runs. Model binaries and scalers should be managed as release artifacts rather than regenerated casually.

## Quick start

### 1. Create the Python environment

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use the Python executable directly or adjust the local execution policy for your user account.

### 2. Start the backend

```powershell
python -m uvicorn backend.server:app --host 0.0.0.0 --port 8000 --reload
```

The API listens on `http://localhost:8000`.

Verify the service:

```powershell
curl http://localhost:8000/api/health
```

Expected response:

```json
{"status":"healthy","service":"sentinelnet-backend"}
```

FastAPI's interactive documentation is available at `http://localhost:8000/docs`.

### 3. Install and start the frontend

In a second terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api/*` requests to `http://localhost:8000`, so both services should be running during live analysis.

## Frontend commands

Run these from `frontend/`:

```powershell
npm run dev       # Start Vite development server on port 5173
npm run build     # Create a production build in frontend/dist
npm run preview   # Preview the production build locally
npm run lint      # Run Oxlint
```

The dashboard also includes a **Load sample** flow backed by static data in `frontend/src/data/mockResult.js`; it does not require the backend.

## Backend API

### `GET /health`

Returns the service and model status.

### `POST /api/analyze`

Send a multipart form upload with the field name `file`:

```powershell
curl -X POST http://localhost:8000/api/analyze `
	-F "file=@path\to\flows.csv"
```

Accepted file extensions are `.csv` and `.pcap`. The endpoint returns HTTP 400 for unsupported extensions and HTTP 500 if inference fails.

The response contains:

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

The complete contract and feature list are maintained in [docs/CONTRACT.md](docs/CONTRACT.md).

## Data and preprocessing

The pipeline is designed for CICFlowMeter-style CSV files. It:

1. Reads UTF-8 CSV data and strips header whitespace.
2. Normalizes common alternate CICFlowMeter column names.
3. Removes repeated header rows.
4. Excludes identifiers and labels from the numeric model input, including `Label`, `Timestamp`, `Flow ID`, IP addresses, and source/destination ports.
5. Converts model features to numeric values and replaces `NaN`, positive infinity, and negative infinity with `0` without dropping rows.
6. Preserves file order and assigns consecutive 200-row windows for the current V4 checkpoint.
7. Aggregates each window into a 156-dimensional state and takes the latest 20 states.
8. Applies the pre-trained `StandardScaler`; it is never fitted on uploaded data.

For reproducible preprocessing, keep feature order synchronized with `model/export_bundle_v4.json`. The current training data did not contain usable destination-port values, so `unique_dst_ports` was effectively always zero during training. This should be addressed with a retrained model before using real port counts for production inference.

## Model limitations

The current model is useful for demonstrating the end-to-end workflow, but its output needs careful interpretation:

- The target is generic **any attack**, not a dedicated infiltration label. `infiltration_timeline` is therefore an attack-risk forecast, not proof of infiltration.
- MITRE stage mapping is partly heuristic and can use file-level attack-family metadata rather than a traffic-derived per-flow stage.
- The current checkpoint uses 200-row pseudo-windows rather than true time windows.
- The reported benchmark is based on a chronological per-file split. Some file test slices contain few or no attack windows, and infiltration-specific performance is weaker than aggregate performance.
- The backend contains a safe fallback response when inference raises an exception. A fallback-shaped response should not be interpreted as a successful model prediction; inspect backend logs when results look suspicious.
- The checked-in V4 artifacts must remain a matched set. Replacing only the checkpoint or scaler can produce invalid predictions without an obvious shape error.

The model handoff and evaluation details are documented in [model/README_LSTM_WORLD_MODEL.md](model/README_LSTM_WORLD_MODEL.md).

## Testing

Run the preprocessing suite from the repository root:

```powershell
python -m pytest tests/test_data_prep.py -v
```

The tests cover column normalization, repeated-header removal, NaN/infinity handling, zero-duration flows, chronological windowing, metadata exclusion, state dimensions, and sequence construction. A full inference test requires a valid matching `model/scaler_v4.pkl` artifact.

For frontend validation:

```powershell
Set-Location frontend
npm run lint
npm run build
```

## Troubleshooting

### `FileNotFoundError` for `scaler_v4.pkl`

Place the scaler from the same training run as `world_model_v4_best.pt` at `model/scaler_v4.pkl`. Do not rename an unrelated scaler to satisfy the import.

### The dashboard cannot reach the API

Confirm that the backend is running on port `8000`, the frontend is running on port `5173`, and the request path is `/api/analyze`. The Vite proxy is configured in `frontend/vite.config.js`.

### Upload returns HTTP 400

The backend checks the filename extension. Rename or export the capture as `.csv` or `.pcap`; other extensions are rejected before inference.

### Upload returns HTTP 500

Check the FastAPI terminal for the traceback. Common causes are missing model artifacts, incompatible feature columns, malformed CSV data, or dependencies missing from the active Python environment.

## Reproducibility and future work

The next model iteration should use real timestamp-based windows, retrain with a populated destination-port feature, separate infiltration from the generic attack target, and strengthen the time-based evaluation split so every attack family is represented appropriately in test data. These changes should be accompanied by a new matched checkpoint, scaler, and export bundle.

## License

No license file is currently included in this repository. Add a license before distributing the project outside its intended team or organization.

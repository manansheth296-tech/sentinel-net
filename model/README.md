# SIH LSTM V4 backend handoff

Files:
- preprocessing.py: raw CSV/Parquet -> 10-second windows -> 156-D states -> (20,156)
- inference.py: loads the V4 model/scaler and exposes `predict()`
- requirements.txt: Python dependencies

Expected model artifacts:
- world_model_v4_best.pt
- scaler_v4.pkl

The V4 notebook defines:
77 raw numeric features
-> mean + std (154)
-> unique_dst_ports (1)
-> flow_count (1)
-> 156-D state
-> 20 consecutive states
-> (20,156) LSTM input.

Important:
The current V4 weights are prototype weights and must be retrained after the
team finalizes the cleaned dataset/preprocessing contract.

The current notebook may use an any-attack proxy for the infiltration target
when no real attack-type label exists. The inference module therefore reports
`attack_risk_probability` and explicitly states this limitation.

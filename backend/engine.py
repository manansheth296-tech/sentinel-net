def run_inference(file_path: str) -> dict:
    """
    Takes a path to a PCAP or CSV file.
    Returns the exact mock JSON contract defined in the execution plan.
    This allows the frontend team to build the UI before the real AI model is ready.
    """
    print(f"Mocking inference for: {file_path}")
    
    # Mock output exactly matching Section 2.2 of the execution plan contract
    return {
        "infiltration_timeline": [
            {"window_start": "2018-02-14T10:00:00", "probability": 0.12},
            {"window_start": "2018-02-14T10:01:00", "probability": 0.34},
            {"window_start": "2018-02-14T10:02:00", "probability": 0.63},
            {"window_start": "2018-02-14T10:03:00", "probability": 0.88}
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
            {"feature": "SYN Flag Count", "importance": 0.31},
            {"feature": "Fwd IAT Mean", "importance": 0.22},
            {"feature": "Flow Duration", "importance": 0.15}
        ],
        "flagged_flows": [
            {"src_ip": "192.168.10.5", "dst_ip": "192.168.10.50", "risk_score": 0.81},
            {"src_ip": "192.168.10.5", "dst_ip": "192.168.10.20", "risk_score": 0.65}
        ],
        "benchmark": {
            "world_model":       {"f1": 0.82, "precision": 0.85, "recall": 0.80, "fpr": 0.04},
            "logistic_baseline": {"f1": 0.65, "precision": 0.68, "recall": 0.62, "fpr": 0.11}
        }
    }

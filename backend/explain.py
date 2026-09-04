"""
SentinelNet — Explainability Engine (backend/explain.py)
Computes feature attributions (SHAP / Gradient Attribution) for the LSTM World Model.
"""

from typing import Dict, List
import numpy as np
import torch
import torch.nn as nn

def explain_prediction(
    model: nn.Module,
    sequence: np.ndarray,
    feature_names: List[str],
    top_k: int = 5,
    device: str = "cpu"
) -> List[Dict[str, float]]:
    """
    Computes feature importance attributions for the LSTM prediction on a (20, 156) sequence.
    
    Uses Integrated Gradients / Input x Gradient attribution on the sequence tensor,
    then aggregates the 156 temporal dimensions (mean/std) back to root network features.
    
    Returns:
        List of dicts: [{"feature": "SYN Flag Count", "importance": 0.32}, ...]
    """
    model.eval()
    dev = torch.device(device)
    
    # sequence shape: (seq_len, input_dim) -> (1, seq_len, input_dim)
    x = torch.from_numpy(sequence.astype(np.float32)).unsqueeze(0).to(dev)
    x.requires_grad = True
    
    # Forward pass through model to get risk logit
    _, risk_logit = model(x)
    
    # Backward pass to compute gradients w.r.t input features
    model.zero_grad()
    risk_logit.backward()
    
    # Input * Absolute Gradient (Feature Attribution)
    # Shape: (1, 20, 156) -> average/max over time steps -> (156,)
    grad = x.grad.detach().cpu().numpy().squeeze(0)
    feat_val = x.detach().cpu().numpy().squeeze(0)
    
    # Focus heavily on the most recent time steps (t-4 to t)
    weights = np.linspace(0.5, 1.0, grad.shape[0])[:, np.newaxis]
    attribution = np.abs(grad * feat_val * weights).mean(axis=0) # (156,)
    
    # Aggregate _mean and _std dimensions back to root feature names
    root_attributions = {}
    for idx, col in enumerate(feature_names):
        val = float(attribution[idx])
        # Clean root feature name
        root_name = col
        if root_name.endswith("_mean"):
            root_name = root_name[:-5]
        elif root_name.endswith("_std"):
            root_name = root_name[:-4]
            
        root_attributions[root_name] = root_attributions.get(root_name, 0.0) + val
        
    # Sort and pick top K
    sorted_feats = sorted(root_attributions.items(), key=lambda item: item[1], reverse=True)
    
    # Top K raw values
    top_items = sorted_feats[:top_k]
    total_val = sum(v for _, v in top_items) if sum(v for _, v in top_items) > 0 else 1.0
    
    # Return normalized importance percentages
    return [
        {
            "feature": feat,
            "importance": round(float(val / total_val), 3)
        }
        for feat, val in top_items
    ]

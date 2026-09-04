
"""
SIH LSTM V4 — inference.py

Backend-facing inference helper.

Expected files:
  world_model_v4_best.pt
  scaler_v4.pkl

Input:
  raw CSV or Parquet containing the CIC-IDS-style flow features.

Output:
  JSON-serializable prediction dictionary containing:
    - attack probability
    - predicted attack flag
    - current MITRE context
    - future risk timeline
    - predicted next states
    - model/input metadata

This module intentionally does NOT claim true infiltration classification when
the training target was only the any-attack proxy.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

from preprocessing import (
    SEQ_LEN,
    preprocess_file,
)


class WorldModelLSTM(nn.Module):
    """Exact V4 architecture from the training notebook."""

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.norm = nn.LayerNorm(hidden_dim)

        self.state_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, input_dim),
        )

        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
        )

    def forward(self, x):
        out, _ = self.lstm(x)
        h = self.norm(out[:, -1, :])

        next_state = self.state_head(h)
        risk_logit = self.infiltration_head(h).squeeze(-1)

        return next_state, risk_logit


class SIHLSTMInference:
    """
    Load the V4 checkpoint + scaler and expose a single predict() method.

    The checkpoint stores:
      input_dim
      feature_cols
      seq_len
      using_real_time
      has_attack_type
    """

    def __init__(
        self,
        checkpoint_path: str,
        scaler_path: str,
        device: Optional[str] = None,
    ):
        self.device = torch.device(
            device
            if device is not None
            else ("cuda" if torch.cuda.is_available() else "cpu")
        )

        self.checkpoint_path = str(checkpoint_path)
        self.scaler_path = str(scaler_path)

        self.checkpoint = torch.load(
            self.checkpoint_path,
            map_location=self.device,
            weights_only=False,
        )

        self.feature_cols = list(self.checkpoint["feature_cols"])
        self.seq_len = int(self.checkpoint.get("seq_len", SEQ_LEN))
        self.input_dim = int(
            self.checkpoint.get("input_dim", len(self.feature_cols))
        )

        self.using_real_time = bool(
            self.checkpoint.get("using_real_time", True)
        )
        self.has_attack_type = bool(
            self.checkpoint.get("has_attack_type", False)
        )

        if self.input_dim != len(self.feature_cols):
            raise ValueError(
                "Checkpoint input_dim does not match feature_cols length."
            )

        self.scaler = __import__("joblib").load(self.scaler_path)

        self.model = WorldModelLSTM(
            input_dim=self.input_dim
        ).to(self.device)

        self.model.load_state_dict(
            self.checkpoint["model_state_dict"]
        )
        self.model.eval()

    @torch.no_grad()
    def _predict_sequence(self, sequence: np.ndarray):
        """
        Run the model on one (20,156) sequence.
        """
        if sequence.shape != (self.seq_len, self.input_dim):
            raise ValueError(
                f"Expected ({self.seq_len}, {self.input_dim}), "
                f"got {sequence.shape}."
            )

        x = torch.from_numpy(
            sequence.astype(np.float32)
        ).unsqueeze(0).to(self.device)

        next_state, risk_logit = self.model(x)
        probability = torch.sigmoid(risk_logit).item()

        return (
            next_state.squeeze(0).cpu().numpy(),
            float(probability),
        )

    @torch.no_grad()
    def _forecast(self, initial_window: np.ndarray, k_steps: int):
        """
        Autoregressive rollout exactly following the V4 notebook:
        predicted next state is appended and the oldest state is removed.
        """
        window = torch.from_numpy(
            initial_window.astype(np.float32)
        ).unsqueeze(0).to(self.device)

        results = []

        for step in range(1, k_steps + 1):
            next_state, risk_logit = self.model(window)
            probability = torch.sigmoid(risk_logit).item()

            results.append(
                {
                    "step_ahead": step,
                    "attack_risk_probability": round(
                        float(probability), 4
                    ),
                    "predicted_state": (
                        next_state.squeeze(0)
                        .cpu()
                        .numpy()
                        .astype(float)
                        .tolist()
                    ),
                }
            )

            window = torch.cat(
                [window[:, 1:, :], next_state.unsqueeze(1)],
                dim=1,
            )

        return results

    def predict(
        self,
        file_path: str,
        k_steps: int = 5,
        threshold: float = 0.5,
    ) -> dict:
        """
        Raw CSV/Parquet -> backend-ready JSON-serializable dictionary.

        Note:
        The current V4 notebook uses the any-attack label as an infiltration
        proxy when a real attack-type/stage target is unavailable. Therefore
        the returned risk is named attack_risk_probability here rather than
        making an unsupported claim of true infiltration classification.
        """
        processed = preprocess_file(
            file_path=file_path,
            feature_cols=self.feature_cols,
            scaler=self.scaler,
            seq_len=self.seq_len,
            use_real_time=self.using_real_time,
        )

        sequence = processed["sequence"]

        _, current_probability = self._predict_sequence(sequence)
        timeline = self._forecast(sequence, k_steps=k_steps)

        last_meta = processed["metadata"][-1]

        return {
            "model_version": "SIH_LSTM_V4",
            "prediction": {
                "attack_risk_probability": round(
                    current_probability, 4
                ),
                "predicted_attack": bool(
                    current_probability >= threshold
                ),
                "threshold": float(threshold),
            },
            "current_context": {
                "mitre_stage": last_meta["mitre_stage"],
                "is_attack": last_meta["is_attack"],
                "flow_count": last_meta["flow_count"],
                "unique_dst_ports": last_meta["unique_dst_ports"],
            },
            "future_timeline": timeline,
            "input_contract": {
                "sequence_shape": [self.seq_len, self.input_dim],
                "window_seconds": processed["schema"]["window_seconds"],
                "raw_feature_count": processed["schema"]["raw_feature_count"],
                "using_real_time_windows": processed["schema"][
                    "using_real_time"
                ],
            },
            "target_note": (
                "Attack-risk target. V4 uses a real attack-type-derived "
                "infiltration target only when attack-type labels exist; "
                "otherwise the notebook uses an any-attack proxy."
            ),
            "status": "PROTOTYPE — retrain on final team-cleaned dataset.",
        }


def predict(
    file_path: str,
    checkpoint_path: str = "world_model_v4_best.pt",
    scaler_path: str = "scaler_v4.pkl",
    k_steps: int = 5,
    threshold: float = 0.5,
) -> dict:
    """
    Simple function for backend/engine.py.

    Example:
        from inference import predict
        result = predict("uploaded_flows.csv")
    """
    engine = SIHLSTMInference(
        checkpoint_path=checkpoint_path,
        scaler_path=scaler_path,
    )
    return engine.predict(
        file_path=file_path,
        k_steps=k_steps,
        threshold=threshold,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SIH LSTM V4 inference"
    )
    parser.add_argument("file", help="Input CSV/Parquet file")
    parser.add_argument(
        "--checkpoint",
        default="world_model_v4_best.pt",
    )
    parser.add_argument(
        "--scaler",
        default="scaler_v4.pkl",
    )
    parser.add_argument(
        "--k-steps",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
    )

    args = parser.parse_args()

    result = predict(
        file_path=args.file,
        checkpoint_path=args.checkpoint,
        scaler_path=args.scaler,
        k_steps=args.k_steps,
        threshold=args.threshold,
    )

    import json
    print(json.dumps(result, indent=2))

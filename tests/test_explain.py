"""
tests/test_explain.py — SHAP explainability pipeline tests

Requires torch + shap (see requirements.txt). Uses a tiny randomly-initialized
WorldModelLSTM (NOT the real checkpoint) purely to validate that the
explainability pipeline's shapes/contract/fallback logic behave correctly —
it does not assert anything about the real model's learned feature
importances (those depend on data the repository does not ship).

Run:
    python -m pytest tests/test_explain.py -v
"""

from __future__ import annotations

import os
import sys
import unittest

import numpy as np

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
for _p in [_PROJECT_ROOT, os.path.join(_PROJECT_ROOT, "backend"), os.path.join(_PROJECT_ROOT, "model2")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import torch
    HAVE_TORCH = True
except ImportError:
    HAVE_TORCH = False

try:
    import shap  # noqa: F401
    HAVE_SHAP = True
except ImportError:
    HAVE_SHAP = False


@unittest.skipUnless(HAVE_TORCH, "torch not installed in this environment")
class TestExplainPipeline(unittest.TestCase):
    def setUp(self):
        from inference import WorldModelLSTM  # model2/inference.py
        self.seq_len = 20
        self.input_dim = 156
        self.model = WorldModelLSTM(input_dim=self.input_dim)
        self.model.eval()
        self.feature_names = (
            [f"feat{i}_mean" for i in range(77)]
            + [f"feat{i}_std" for i in range(77)]
            + ["unique_dst_ports", "flow_count"]
        )
        rng = np.random.default_rng(0)
        self.sequence = rng.normal(size=(self.seq_len, self.input_dim)).astype(np.float32)
        self.background = rng.normal(size=(12, self.seq_len, self.input_dim)).astype(np.float32)
        self.all_states = rng.normal(size=(30, self.input_dim)).astype(np.float32)

    def test_falls_back_without_background(self):
        from explain import explain_prediction
        result = explain_prediction(self.model, self.sequence, self.feature_names, background_sequences=None)
        self.assertTrue(result["method"].startswith("Permutation Importance"))
        self.assertFalse(result["temporal_explanation"]["available"])
        self.assertTrue(len(result["local_explanation"]) > 0)

    @unittest.skipUnless(HAVE_SHAP, "shap package not installed in this environment")
    def test_uses_shap_with_background(self):
        from explain import explain_prediction
        result = explain_prediction(
            self.model, self.sequence, self.feature_names,
            background_sequences=self.background,
            all_window_states=self.all_states,
        )
        self.assertIn("GradientExplainer", result["method"])
        self.assertTrue(result["temporal_explanation"]["available"])
        self.assertEqual(len(result["temporal_explanation"]["steps"]), self.seq_len)
        self.assertTrue(len(result["local_explanation"]) > 0)
        for row in result["local_explanation"]:
            self.assertIn(row["direction"], ("increases attack risk", "decreases attack risk", "no measurable effect"))

    def test_feature_names_reduced_to_raw_names(self):
        from explain import explain_prediction
        result = explain_prediction(self.model, self.sequence, self.feature_names, background_sequences=None)
        returned_names = {r["feature"] for r in result["local_explanation"]}
        # None of the returned names should still carry the _mean/_std suffix.
        for name in returned_names:
            self.assertFalse(name.endswith("_mean"))
            self.assertFalse(name.endswith("_std"))

    def test_no_fabricated_global_explanation_without_enough_windows(self):
        from explain import explain_prediction
        result = explain_prediction(
            self.model, self.sequence, self.feature_names,
            background_sequences=self.background,
            all_window_states=self.all_states[:2],  # too few for a real global estimate
        )
        self.assertFalse(result["global_explanation"]["available"])


if __name__ == "__main__":
    unittest.main()

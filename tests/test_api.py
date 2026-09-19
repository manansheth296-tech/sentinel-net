"""
tests/test_api.py — FastAPI backend layer tests

Requires fastapi, torch, joblib, scikit-learn (see requirements.txt) and the
real model2/ checkpoint + scaler shipped in this repository. Run:

    python -m pytest tests/test_api.py -v
"""

from __future__ import annotations

import io
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed in this environment")
class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.api import app
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("status", body)
        self.assertIn("model_version", body)

    def test_model_endpoint_has_limitations(self):
        r = self.client.get("/api/model")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("limitations", body)
        self.assertTrue(len(body["limitations"]) > 0)

    def test_mitre_endpoint(self):
        r = self.client.get("/api/mitre")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["type"], "rule-based lookup table, not a learned classifier")
        self.assertIn("Benign", body["mapping"])

    def test_analyze_rejects_bad_extension(self):
        r = self.client.post(
            "/api/analyze",
            files={"file": ("capture.exe", io.BytesIO(b"not a flow file"), "application/octet-stream")},
        )
        self.assertEqual(r.status_code, 400)

    def test_analyze_rejects_empty_file(self):
        r = self.client.post(
            "/api/analyze",
            files={"file": ("capture.csv", io.BytesIO(b""), "text/csv")},
        )
        self.assertEqual(r.status_code, 400)

    def test_analyze_rejects_malformed_schema(self):
        bad_csv = b"col_a,col_b\n1,2\n3,4\n"
        r = self.client.post(
            "/api/analyze",
            files={"file": ("capture.csv", io.BytesIO(bad_csv), "text/csv")},
        )
        # Missing Label column / feature columns -> a real, explicit error,
        # never a fabricated "successful" analysis.
        self.assertEqual(r.status_code, 422)
        body = r.json()
        self.assertTrue(body.get("error"))
        self.assertIn("message", body)


if __name__ == "__main__":
    unittest.main()

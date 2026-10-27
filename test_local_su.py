# Local test suite for incident-triage agent
# Tests all the categories the grader checks

import sys
import json
import hashlib
import os
import tempfile
import sqlite3
import unittest
from unittest.mock import patch, MagicMock

# Add the project to the path
sys.path.insert(0, '.')

from main import (
    app, db, canonical, digest, valid_id, parse_trace_context,
    span, make_span, create_trace, planner, normalize_plan,
    catalog_map, make_dispatch, public_state, save_run, load_run
)
from fastapi.testclient import TestClient

client = TestClient(app)

# Test data
TEST_BODY = {
    "profile": "ga5-incident-agent/v2",
    "runId": "local-test-run-001",
    "publicMarker": "test-marker",
    "incident": {
        "incidentId": "INC-LOCAL-001",
        "title": "Synthetic API errors",
        "service": "demo-api",
        "severity": "SEV-2",
        "transcript": "[ev-A] api errors rose after deploy\n[ev-B] pool at 95%\n[ev-C] db slow after deploy",
        "allowedRootCauses": ["deployment_regression", "database_connection_exhaustion", "unknown"]
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "Read-only check of metrics",
         "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}},
                         "required": ["service"], "additionalProperties": False}},
        {"name": "page_owner", "description": "Send service owner notification",
         "inputSchema": {"type": "object", "properties": {"service": {"type": "string"},
                                                        "reason": {"type": "string"}},
                         "required": ["service", "reason"], "additionalProperties": False}}
    ],
    "policy": {
        "maximumDiagnostics": 2,
        "effectTools": ["page_owner"],
        "approvalRequiredFor": []
    }
}

class TestHealthEndpoint(unittest.TestCase):
    """1. Verify /health endpoint returns 200"""
    def test_health(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_health_content_type(self):
        response = client.get("/health")
        self.assertIn("application/json", response.headers.get("content-type", ""))


class TestProposeEndpoint(unittest.TestCase):
    """2. Verify POST /v2/incidents correct status, response, and phases"""
    def setUp(self):
        # Use in-memory sqlite for tests
        # db() is a standalone function, not app.db()
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_db.close()
        self.original_db_path = None
        # Patch the DB_PATH constant used by db()
        import main
        self.original_db_path = main.DB_PATH
        import os as _os
        main.DB_PATH = self.tmp_db.name
        # Initialize the database
        import main
        main.db()

    def tearDown(self):
        import main
        import os
        if hasattr(main, 'DB_PATH'):
            main.DB_PATH = self.original_db_path
        os.unlink(self.tmp_db.name)

    def test_propose_returns_200(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body.get("status"), "waiting")
        self.assertIn("runId", body)
        self.assertIn("diagnosis", body)
        self.assertIn("dispatches", body)

    def test_propose_returns_phase_diagnostics(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        body = response.json()
        self.assertEqual(body.get("phase"), "diagnostics")

    def test_propose_returns_diagnosis_with_evidence(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        body = response.json()
        self.assertIn("rootCause", body["diagnosis"])
        self.assertIn("evidence", body["diagnosis"])
        self.assertGreaterEqual(len(body["diagnosis"]["evidence"]), 2)

    def test_propose_returns_diagnostic_dispatch_before_effect(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        body = response.json()
        self.assertEqual(len(body["dispatches"]), 1)
        self.assertEqual(body["dispatches"][0]["phase"], "diagnostic")
        self.assertEqual(body["dispatches"][0]["toolName"], "query_metrics")
        self.assertNotIn("approval_gate", body)

    def test_propose_returns_valid_rootCause(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        body = response.json()
        self.assertIn(body["diagnosis"]["rootCause"], TEST_BODY["incident"]["allowedRootCauses"])

    def test_propose_returns_correct_content_type(self):
        response = client.post("/v2/incidents", json=TEST_BODY)
        self.assertIn("application/json", response.headers.get("content-type", ""))

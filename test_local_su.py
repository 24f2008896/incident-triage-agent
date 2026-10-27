# Local test suite for incident-triage agent (updated for v2 contract)
import sys, json, hashlib, os, tempfile, copy, uuid, unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

sys.path.insert(0, '.')
import main
from main import app

client = TestClient(app)

BASE_BODY = {
    "profile": "ga5-incident-agent/v2",
    "runId": "local-test-run-" + uuid.uuid4().hex[:8],
    "publicMarker": "test-marker",
    "incident": {
        "incidentId": "INC-LOCAL-001",
        "title": "Synthetic API errors",
        "service": "demo-api",
        "severity": "SEV-2",
        "transcript": "[ev-A] api errors rose after deploy\n[ev-B] pool at 95%\n[ev-C] db slow after deploy",
        "allowedRootCauses": ["deployment_regression", "database_connection_exhaustion", "unknown"],
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "Read-only check of metrics",
         "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}},
                         "required": ["service"], "additionalProperties": False}},
        {"name": "page_owner", "description": "Send service owner notification",
         "inputSchema": {"type": "object", "properties": {"service": {"type": "string"},
                                                         "reason": {"type": "string"}},
                         "required": ["service", "reason"], "additionalProperties": False}},
    ],
    "policy": {"maximumDiagnostics": 2, "effectTools": ["page_owner"],
               "approvalRequiredFor": []},
}

PLAN = {
    "rootCause": "deployment_regression",
    "evidence": ["ev-A", "ev-B"],
    "diagnostics": [
        {"toolName": "query_metrics", "arguments": {"service": "demo-api"}, "evidence": ["ev-A"]},
    ],
    "chosenEffect": "page_owner",
    "effectArguments": {"service": "demo-api", "reason": "SEV-2 API errors after deploy"},
}


def fresh_body():
    b = copy.deepcopy(BASE_BODY)
    b["runId"] = "local-test-run-" + uuid.uuid4().hex[:8]
    return b


class TestHealthEndpoint(unittest.TestCase):
    def test_health(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


class TestProposeEndpoint(unittest.TestCase):
    def setUp(self):
        import main as _m
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_db.close()
        self.original_db_path = _m.DB_PATH
        _m.DB_PATH = self.tmp_db.name
        _m.db()

    def tearDown(self):
        import main as _m, os
        _m.DB_PATH = self.original_db_path
        os.unlink(self.tmp_db.name)

    def _post(self, body=None):
        import main as _m
        _m.planner = lambda b: copy.deepcopy(PLAN)
        return client.post("/v2/incidents", json=body or fresh_body())

    def test_propose_returns_200(self):
        response = self._post()
        self.assertEqual(response.status_code, 200)

    def test_propose_shape(self):
        body = self._post().json()
        self.assertEqual(body["status"], "waiting")
        self.assertIn("runId", body)
        self.assertIn("diagnosis", body)
        self.assertIn("dispatches", body)
        self.assertIn("approvals", body)
        self.assertNotIn("phase", body)
        self.assertNotIn("proposal", body)

    def test_propose_returns_diagnosis_with_evidence(self):
        body = self._post().json()
        self.assertIn("rootCause", body["diagnosis"])
        self.assertIn("evidence", body["diagnosis"])
        self.assertGreaterEqual(len(body["diagnosis"]["evidence"]), 2)
        self.assertLessEqual(len(body["diagnosis"]["evidence"]), 4)

    def test_propose_returns_diagnostic_dispatch_before_effect(self):
        body = self._post().json()
        self.assertEqual(len(body["dispatches"]), 1)
        self.assertEqual(body["dispatches"][0]["phase"], "diagnostic")
        self.assertEqual(body["dispatches"][0]["toolName"], "query_metrics")
        self.assertEqual(body["approvals"], [])

    def test_propose_returns_valid_rootCause(self):
        body = self._post().json()
        self.assertIn(body["diagnosis"]["rootCause"], BASE_BODY["incident"]["allowedRootCauses"])

    def test_propose_traceparent_format(self):
        body = self._post().json()
        tp = body["dispatches"][0]["traceparent"]
        parts = tp.split("-")
        self.assertEqual(len(parts), 4)
        self.assertEqual(len(parts[1]), 32)
        self.assertEqual(len(parts[2]), 16)

    def test_propose_no_sensitive_leak(self):
        text = self._post().text
        self.assertNotIn("DO-NOT-SEND-TO-MODEL", text)


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        import main as _m
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_db.close()
        self.original_db_path = _m.DB_PATH
        _m.DB_PATH = self.tmp_db.name
        _m.db()

    def tearDown(self):
        import main as _m, os
        _m.DB_PATH = self.original_db_path
        os.unlink(self.tmp_db.name)

    def test_full_flow_no_approval(self):
        import main as _m
        _m.planner = lambda b: copy.deepcopy(PLAN)
        response = client.post("/v2/incidents", json=fresh_body())
        self.assertEqual(response.status_code, 200)
        st = response.json()
        d = st["dispatches"][0]
        rid = st["runId"]
        r2 = client.post(f"/v2/incidents/{rid}/receipts", json={
            "receiptId": "rcpt-" + uuid.uuid4().hex[:8],
            "outcomes": [{"actionId": d["actionId"], "callId": d["callId"], "attempt": 1,
                          "status": 200, "resultClass": "diagnosis_confirmed",
                          "nonce": "nonce-" + uuid.uuid4().hex[:8]}]})
        self.assertEqual(r2.status_code, 200)
        st2 = r2.json()
        self.assertEqual(st2["status"], "waiting")
        self.assertEqual(len(st2["dispatches"]), 1)
        self.assertEqual(st2["dispatches"][0]["phase"], "effect")
        ed = st2["dispatches"][0]
        r3 = client.post(f"/v2/incidents/{rid}/receipts", json={
            "receiptId": "rcpt-" + uuid.uuid4().hex[:8],
            "outcomes": [{"actionId": ed["actionId"], "callId": ed["callId"], "attempt": 1,
                          "status": 200, "resultClass": "done",
                          "nonce": "nonce-" + uuid.uuid4().hex[:8]}]})
        self.assertEqual(r3.status_code, 200)
        st3 = r3.json()
        self.assertEqual(st3["status"], "completed")
        self.assertEqual(st3["chosenEffect"], "page_owner")
        self.assertEqual(st3["dispatches"], [])
        self.assertEqual(st3["approvals"], [])
        self.assertIsInstance(st3["actionLog"], list)
        self.assertIsInstance(st3["receiptLog"], list)
        self.assertIsInstance(st3["otlp"], dict)

    def test_conflict_and_replay(self):
        import main as _m
        _m.planner = lambda b: copy.deepcopy(PLAN)
        body = fresh_body()
        r1 = client.post("/v2/incidents", json=body).json()
        r2 = client.post("/v2/incidents", json=body)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json(), r1)
        b2 = copy.deepcopy(body)
        b2["publicMarker"] = "changed"
        r3 = client.post("/v2/incidents", json=b2)
        self.assertEqual(r3.status_code, 409)


if __name__ == "__main__":
    import unittest
    unittest.main()

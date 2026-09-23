"""
Tests for Risk Alert intake, UiPath RPA integration, automated email alerts, and callbacks.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import get_db
from app.models.incident import Incident
from app.models.uipath_action import UiPathAction
from app.models.audit_log import AuditLog


@pytest.fixture
def client(db_session: Session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestRiskAlertWorkflow:
    def test_high_risk_alert_triggers_uipath_and_email(self, client: TestClient, db_session: Session):
        payload = {
            "url": "http://secure-login-paypal.phish-attack.xyz/verify?token=abc123",
            "risk_score": 94,
            "classification": "HIGH_RISK",
            "reasons": [
                "Deceptive top-level domain (.xyz)",
                "PayPal credential harvest pattern detected",
                "Known threat indicator"
            ],
            "incident_id": "INC-TEST-HIGH-01"
        }
        response = client.post("/api/risk-alert", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert data["risk_level"] == "HIGH"
        assert data["incident_id"] == "INC-TEST-HIGH-01"
        assert data["uipath_status"] in ("TRIGGERED", "SUCCESS")
        assert data["email_status"] in ("TEST_MODE_LOGGED", "QUEUED", "SENT")
        assert data["execution_id"] is not None
        assert data["execution_id"].startswith("UIPATH-")

        # Verify Incident was created in DB
        inc = db_session.query(Incident).filter(Incident.incident_number == "INC-TEST-HIGH-01").first()
        assert inc is not None
        assert inc.severity == "HIGH"
        assert inc.url == payload["url"]

        # Verify UiPathAction record exists
        action = db_session.query(UiPathAction).filter(UiPathAction.execution_id == data["execution_id"]).first()
        assert action is not None
        assert action.action_type == "NOTIFY_SOC"
        assert action.email_status in ("TEST_MODE_LOGGED", "QUEUED", "SENT")
        assert action.alert_type == "RISK_ALERT"

        # Verify Audit Log entry
        logs = db_session.query(AuditLog).filter(AuditLog.entity_id == data["execution_id"]).all()
        assert len(logs) > 0

    def test_medium_risk_alert_logs_without_high_priority_uipath(self, client: TestClient, db_session: Session):
        payload = {
            "url": "https://unverified-fileshare-portal.net/download/invoice.pdf",
            "risk_score": 50,
            "classification": "SUSPICIOUS",
            "reasons": ["Newly registered domain (3 days old)"],
            "incident_id": "INC-TEST-MED-01"
        }
        response = client.post("/api/risk-alert", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert data["risk_level"] == "MEDIUM"
        assert data["incident_id"] == "INC-TEST-MED-01"
        assert data["uipath_status"] == "SKIPPED"
        assert data["email_status"] in ("SKIPPED", "TEST_MODE_LOGGED", "QUEUED")

        inc = db_session.query(Incident).filter(Incident.incident_number == "INC-TEST-MED-01").first()
        assert inc is not None
        assert inc.severity == "MEDIUM"

    def test_low_risk_alert_records_only(self, client: TestClient, db_session: Session):
        payload = {
            "url": "https://github.com/fredolin0109-hub/Aegstrace-ai",
            "risk_score": 10,
            "classification": "SAFE",
            "reasons": ["High domain reputation score"],
            "incident_id": "INC-TEST-LOW-01"
        }
        response = client.post("/api/risk-alert", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert data["risk_level"] == "LOW"
        assert data["uipath_status"] == "SKIPPED"
        assert data["email_status"] == "SKIPPED"

    def test_validation_errors(self, client: TestClient):
        # Empty URL
        res1 = client.post("/api/risk-alert", json={"url": "   ", "risk_score": 90, "classification": "HIGH_RISK"})
        assert res1.status_code == 422

        # Invalid risk_score > 100
        res2 = client.post("/api/risk-alert", json={"url": "https://example.com", "risk_score": 150, "classification": "HIGH_RISK"})
        assert res2.status_code == 422

        # Invalid risk_score < 0
        res3 = client.post("/api/risk-alert", json={"url": "https://example.com", "risk_score": -5, "classification": "HIGH_RISK"})
        assert res3.status_code == 422

    def test_idempotent_duplicate_suppression(self, client: TestClient):
        payload = {
            "url": "http://idempotency-test-phish.xyz/login",
            "risk_score": 92,
            "classification": "HIGH_RISK",
            "reasons": ["Suspicious login prompt"],
            "incident_id": "INC-TEST-IDEM-01"
        }
        res1 = client.post("/api/risk-alert", json=payload)
        assert res1.status_code == 200
        exec_id1 = res1.json()["execution_id"]

        # Immediate replay should be caught by idempotency
        res2 = client.post("/api/risk-alert", json=payload)
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["execution_id"] == exec_id1
        assert "Duplicate alert suppressed" in data2["message"]


class TestUiPathCallbackAndRetry:
    def test_uipath_callback_updates_status_and_audit(self, client: TestClient, db_session: Session):
        # Step 1: Create high-risk alert
        alert_res = client.post("/api/risk-alert", json={
            "url": "http://callback-test.com/payload.exe",
            "risk_score": 95,
            "classification": "HIGH_RISK",
            "reasons": ["Binary payload from IP"],
            "incident_id": "INC-TEST-CB-01"
        })
        exec_id = alert_res.json()["execution_id"]

        # Step 2: UiPath callback confirms completion and email delivery
        callback_payload = {
            "incident_id": "INC-TEST-CB-01",
            "execution_id": exec_id,
            "status": "COMPLETED",
            "email_status": "SENT",
            "timestamp": "2026-09-23T11:00:00Z",
            "details": {"action_confirmed": True, "robot_id": "ROBOT-ALPHA"}
        }
        cb_res = client.post("/api/uipath/callback", json=callback_payload)
        assert cb_res.status_code == 200
        assert cb_res.json()["success"] is True
        assert cb_res.json()["updated_status"] == "COMPLETED"

        # Verify database record updated
        action = db_session.query(UiPathAction).filter(UiPathAction.execution_id == exec_id).first()
        assert action.status == "COMPLETED"
        assert action.email_status == "SENT"
        assert action.completed_at is not None

    def test_uipath_callback_nonexistent_returns_404(self, client: TestClient):
        cb_res = client.post("/api/uipath/callback", json={
            "incident_id": "INC-DOES-NOT-EXIST",
            "execution_id": "UIPATH-NONEXISTENT",
            "status": "COMPLETED",
        })
        assert cb_res.status_code == 404

    def test_uipath_retry_mechanism(self, client: TestClient, db_session: Session):
        # Seed an incident
        alert_res = client.post("/api/risk-alert", json={
            "url": "http://retry-target.com/page",
            "risk_score": 88,
            "classification": "HIGH_RISK",
            "reasons": ["Suspicious script tags"],
            "incident_id": "INC-TEST-RETRY-01"
        })
        assert alert_res.status_code == 200

        # Execute retry
        retry_res = client.post("/api/uipath/retry", json={
            "incident_id": "INC-TEST-RETRY-01",
            "retry_type": "ALL"
        })
        assert retry_res.status_code == 200
        retry_data = retry_res.json()
        assert retry_data["success"] is True
        assert retry_data["uipath_status"] == "TRIGGERED"
        assert retry_data["execution_id"].startswith("UIPATH-RETRY-")

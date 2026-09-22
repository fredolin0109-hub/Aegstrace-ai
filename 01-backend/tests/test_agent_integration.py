import pytest
from app.models.agent_action import AgentAction
from app.models.incident import Incident
from app.models.uipath_action import UiPathAction
from app.models.url_scan import URLScan


def test_investigate_e2e_persists_action_trace(client, db_session):
    """Verify end-to-end investigation persists all 5 phases into database agent_actions."""
    payload = {
        "url": "https://www.google.com",
        "depth": "standard",
        "force_escalate": False,
    }
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["url"] == "https://www.google.com"
    assert data["classification"] == "SAFE"
    assert data["decision"] == "SAFE_PASS"
    assert data["incident_created"] is False
    assert data["initial_risk_score"] < 0.35

    # Check action trace response items
    trace_items = data["action_trace"]
    action_types = [item["action_type"] for item in trace_items]
    assert "DETECT" in action_types
    assert "INVESTIGATE" in action_types
    assert "DECIDE" in action_types
    assert "ACT" in action_types
    assert "VERIFY" in action_types

    # Verify rows in database
    db_actions = db_session.query(AgentAction).all()
    assert len(db_actions) >= 5
    db_action_types = [a.action_type for a in db_actions]
    assert "DETECT" in db_action_types
    assert "INVESTIGATE" in db_action_types
    assert "DECIDE" in db_action_types
    assert "ACT" in db_action_types
    assert "VERIFY" in db_action_types


def test_investigate_high_risk_triggers_incident_and_uipath(client, db_session):
    """Verify high-risk phishing investigation generates Incident and dispatches UiPath RPA."""
    payload = {
        "url": "http://192.168.1.100/chase-online-login-verify.php",
        "depth": "deep",
        "force_escalate": False,
    }
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "HIGH_RISK"
    assert data["decision"] == "TRIGGER_AUTOMATED_RESPONSE"
    assert data["incident_created"] is True
    assert data["incident_id"] is not None
    assert data["incident_number"].startswith("INC-")
    assert data["recommended_action"] == "BLOCK_AND_CONTAIN"
    assert len(data["evidence_collected"]) > 0

    # Verify Incident record in database
    incident = db_session.query(Incident).filter(Incident.id == data["incident_id"]).first()
    assert incident is not None
    assert incident.url == payload["url"]
    assert incident.severity in ("HIGH", "CRITICAL")
    assert incident.status in ("CONTAINED", "OPEN", "INVESTIGATING")

    # Verify UiPath RPA execution record in database
    uipath_action = db_session.query(UiPathAction).filter(UiPathAction.incident_id == incident.id).first()
    assert uipath_action is not None
    assert uipath_action.action_type == "CONTAIN_HOST"
    assert uipath_action.status in ("SIMULATED", "SUCCESS")
    assert uipath_action.execution_id.startswith("EXEC-UIPATH-")


def test_investigate_with_existing_url_scan_id(client, db_session):
    """Verify investigation can link to and reuse an existing URLScan."""
    # 1. Perform initial scan via analyze endpoint
    scan_resp = client.post("/api/analyze", json={"url": "https://wikipedia.org"})
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["id"]

    # 2. Investigate referencing scan_id
    inv_payload = {
        "url": "https://wikipedia.org",
        "url_scan_id": scan_id,
        "depth": "standard",
    }
    inv_resp = client.post("/api/investigate", json=inv_payload)
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()

    assert inv_data["url_scan_id"] == scan_id
    assert inv_data["decision"] == "SAFE_PASS"

    # Verify AgentAction records reference scan_id
    actions = db_session.query(AgentAction).filter(AgentAction.url_scan_id == scan_id).all()
    assert len(actions) >= 5


def test_investigate_validation_error(client):
    """Verify 422 Unprocessable Entity when URL is invalid or empty."""
    response = client.post("/api/investigate", json={"url": "a"})
    assert response.status_code == 422

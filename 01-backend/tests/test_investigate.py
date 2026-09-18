def test_investigate_benign_url(client):
    payload = {
        "url": "https://www.wikipedia.org",
        "depth": "standard",
        "force_escalate": False
    }
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.wikipedia.org"
    assert data["classification"] == "SAFE"
    assert data["decision"] == "SAFE_PASS"
    assert data["incident_created"] is False
    assert len(data["action_trace"]) >= 3
    actions = [a["action_type"] for a in data["action_trace"]]
    assert "DETECT" in actions
    assert "INVESTIGATE" in actions
    assert "DECIDE" in actions


def test_investigate_high_risk_url_triggers_incident(client):
    payload = {
        "url": "http://10.0.0.1/banking-login-auth-verify.php",
        "depth": "deep",
        "force_escalate": False
    }
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "HIGH_RISK"
    assert data["incident_created"] is True
    assert data["incident_id"] is not None
    assert data["incident_number"] is not None
    assert data["decision"] in ("TRIGGER_AUTOMATED_RESPONSE", "ESCALATE_INCIDENT")
    assert len(data["evidence_collected"]) > 0


def test_investigate_force_escalation(client):
    payload = {
        "url": "https://unknown-internal-site.local",
        "depth": "deep",
        "force_escalate": True
    }
    response = client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["incident_created"] is True
    assert data["incident_id"] is not None

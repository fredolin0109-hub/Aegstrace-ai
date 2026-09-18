def test_trigger_uipath_action_success(client):
    # 1. First create an incident to attach to
    inc_res = client.post("/api/incidents", json={
        "url": "http://192.168.1.100/steal-creds",
        "title": "Malicious Phishing Portal",
        "description": "High risk site needing automated firewall containment",
        "severity": "CRITICAL"
    })
    incident_id = inc_res.json()["id"]

    # 2. Trigger UiPath action
    trigger_payload = {
        "incident_id": incident_id,
        "action_type": "CONTAIN_HOST",
        "parameters": {"target_ip": "192.168.1.100", "duration_hours": 24}
    }
    trigger_res = client.post("/api/uipath/trigger", json=trigger_payload)
    assert trigger_res.status_code == 202
    action_data = trigger_res.json()
    assert action_data["incident_id"] == incident_id
    assert action_data["action_type"] == "CONTAIN_HOST"
    assert action_data["status"] == "SIMULATED"
    assert action_data["execution_id"].startswith("EXEC-UIPATH-")

    execution_id = action_data["execution_id"]

    # 3. Check status via polling endpoint
    status_res = client.get(f"/api/uipath/status/{execution_id}")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["execution_id"] == execution_id
    assert status_data["status"] == "SIMULATED"
    assert status_data["progress_percentage"] == 100
    assert status_data["is_simulation"] is True

    # 4. Check that containment action updated the incident status to CONTAINED
    updated_inc = client.get(f"/api/incidents/{incident_id}").json()
    assert updated_inc["status"] == "CONTAINED"
    assert len(updated_inc["uipath_actions"]) == 1


def test_trigger_uipath_invalid_action(client):
    inc_res = client.post("/api/incidents", json={
        "url": "https://test.com",
        "title": "Test Phishing Incident",
        "description": "Valid incident description for testing invalid action",
        "severity": "LOW"
    })
    assert inc_res.status_code == 201
    incident_id = inc_res.json()["id"]

    res = client.post("/api/uipath/trigger", json={
        "incident_id": incident_id,
        "action_type": "NON_EXISTENT_ACTION"
    })
    assert res.status_code == 400


def test_trigger_uipath_nonexistent_incident(client):
    res = client.post("/api/uipath/trigger", json={
        "incident_id": 99999,
        "action_type": "NOTIFY_SOC"
    })
    assert res.status_code == 404


def test_get_uipath_status_not_found(client):
    res = client.get("/api/uipath/status/EXEC-UIPATH-NONEXISTENT")
    assert res.status_code == 404

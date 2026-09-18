def test_create_and_get_incident(client):
    create_payload = {
        "url": "https://malicious-bank-login.xyz",
        "title": "Phishing Impersonation Attempt",
        "description": "Suspicious login form targeting banking credentials",
        "severity": "HIGH",
        "assigned_to": "Tier1_Analyst",
    }
    create_res = client.post("/api/incidents", json=create_payload)
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["id"] is not None
    assert created_data["incident_number"].startswith("INC-")
    assert created_data["severity"] == "HIGH"
    assert created_data["status"] == "OPEN"

    incident_id = created_data["id"]

    # Get single incident
    get_res = client.get(f"/api/incidents/{incident_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == incident_id
    assert get_res.json()["title"] == "Phishing Impersonation Attempt"


def test_list_incidents_with_filtering(client):
    # Create multiple incidents
    client.post("/api/incidents", json={
        "url": "https://threat1.com",
        "title": "Threat 1",
        "description": "Description 1",
        "severity": "CRITICAL"
    })
    client.post("/api/incidents", json={
        "url": "https://threat2.com",
        "title": "Threat 2",
        "description": "Description 2",
        "severity": "LOW"
    })

    # List all
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2

    # Filter by severity
    res_crit = client.get("/api/incidents?severity=CRITICAL")
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    assert all(item["severity"] == "CRITICAL" for item in crit_data["items"])


def test_update_incident_status(client):
    create_res = client.post("/api/incidents", json={
        "url": "https://threat-update.com",
        "title": "Threat for Update",
        "description": "Description",
        "severity": "MEDIUM"
    })
    incident_id = create_res.json()["id"]

    # Update status to CONTAINED
    patch_res = client.patch(f"/api/incidents/{incident_id}", json={
        "status": "CONTAINED",
        "assigned_to": "SOC_Commander"
    })
    assert patch_res.status_code == 200
    updated_data = patch_res.json()
    assert updated_data["status"] == "CONTAINED"
    assert updated_data["assigned_to"] == "SOC_Commander"
    assert updated_data["resolved_at"] is not None


def test_get_nonexistent_incident(client):
    res = client.get("/api/incidents/999999")
    assert res.status_code == 404

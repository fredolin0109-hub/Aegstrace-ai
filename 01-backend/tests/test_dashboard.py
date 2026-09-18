def test_dashboard_stats_aggregation(client):
    # Scan a safe URL
    client.post("/api/analyze", json={"url": "https://trusted-portal.com"})
    # Scan a phishing URL
    client.post("/api/analyze", json={"url": "http://10.20.30.40/login-paypal.xyz"})

    # Create an incident
    inc_res = client.post("/api/incidents", json={
        "url": "http://10.20.30.40/login-paypal.xyz",
        "title": "Phishing Alert",
        "description": "Critical phish detected",
        "severity": "HIGH",
    })
    incident_id = inc_res.json()["id"]

    # Trigger a UiPath response
    client.post("/api/uipath/trigger", json={
        "incident_id": incident_id,
        "action_type": "CREATE_TICKET",
    })

    # Fetch dashboard stats
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()

    assert data["total_scans"] >= 2
    assert data["safe_urls"] >= 1
    assert data["high_risk_urls"] >= 1
    assert data["active_incidents"] >= 1
    assert data["automated_responses"] >= 1
    assert "severity_breakdown" in data
    assert "status_breakdown" in data
    assert len(data["recent_scans"]) >= 2
    assert len(data["recent_incidents"]) >= 1

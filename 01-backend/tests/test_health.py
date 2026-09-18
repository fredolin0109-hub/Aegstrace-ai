def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "AEGISTRACE Cybersecurity Platform"
    assert data["status"] == "online"
    assert "health_check" in data


def test_health_check_healthy(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "healthy"
    assert "timestamp" in data
    assert "version" in data

def test_analyze_benign_url(client):
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["domain"] == "www.google.com"
    assert data["classification"] == "SAFE"
    assert data["risk_score"] < 0.35
    assert data["recommendation"] == "ALLOW"
    assert "features" in data
    assert data["features"]["is_https"] is True


def test_analyze_suspicious_phishing_url(client):
    payload = {"url": "http://192.168.1.50/login-paypal-verify.php?auth=true"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "HIGH_RISK"
    assert data["risk_score"] >= 0.70
    assert data["recommendation"] == "BLOCK"
    assert len(data["indicators"]) > 0
    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "IP_HOST" in indicator_types


def test_analyze_suspicious_tld_and_subdomains(client):
    payload = {"url": "http://secure.account.billing.update.verify.evil-login.xyz/signin"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 0.35
    assert data["classification"] in ("SUSPICIOUS", "HIGH_RISK")
    assert len(data["indicators"]) > 0


def test_analyze_missing_or_invalid_url(client):
    # Empty string should fail validation
    response = client.post("/api/analyze", json={"url": ""})
    assert response.status_code in (400, 422)

    # Missing url key
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422

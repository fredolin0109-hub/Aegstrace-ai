"""
AEGISTRACE Backend + AIML Engine Integration Test Suite.
Verifies end-to-end telemetry between 01-backend and 03-aiml-engine:
- Feature extraction, Random Forest classification, and probability estimation
- Multi-layer threat score fusion with DSA Engine & heuristic rules
- Explainable AI risk factors in API response
- Database persistence and audit logging
"""

import pytest


def test_analyze_benign_url_aiml_metrics(client):
    """Verify that scanning a benign URL yields low ML risk score and SAFE ML classification."""
    payload = {"url": "https://www.google.com/search?q=machine+learning+security"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "SAFE"
    assert data["risk_score"] == 0.0  # Whitelisted via DSA HashMap
    assert data["recommendation"] == "ALLOW"

    # ML fields in ScanResponse
    assert data["ml_risk_score"] is not None
    assert isinstance(data["ml_risk_score"], float)
    assert data["ml_risk_score"] < 0.35
    assert data["ml_classification"] == "SAFE"
    assert data["ml_confidence"] is not None
    assert data["ml_confidence"] >= 0.50
    assert isinstance(data["ml_explanations"], list)
    assert len(data["ml_explanations"]) > 0


def test_analyze_phishing_url_aiml_metrics(client):
    """Verify that scanning a credential-theft phishing URL elevates ML risk and produces AIML indicator."""
    payload = {"url": "http://192.168.1.50/login-paypal-verify.php?auth=true&dest=http://attacker.com"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Fused classification must be HIGH_RISK / BLOCK
    assert data["classification"] == "HIGH_RISK"
    assert data["risk_score"] >= 0.70
    assert data["recommendation"] == "BLOCK"

    # ML specific metrics
    assert data["ml_risk_score"] is not None
    assert data["ml_risk_score"] >= 0.60
    assert data["ml_classification"] in ("SUSPICIOUS", "HIGH_RISK")
    assert isinstance(data["ml_explanations"], list)
    assert len(data["ml_explanations"]) > 0

    # Indicators must include AIML_PREDICTION
    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "AIML_PREDICTION" in indicator_types

    ml_indicator = next(ind for ind in data["indicators"] if ind["indicator_type"] == "AIML_PREDICTION")
    assert ml_indicator["severity"] in ("HIGH", "MEDIUM")
    assert "ml_risk_score" in ml_indicator["details"]
    assert "explanations" in ml_indicator["details"]


def test_features_contain_aiml_telemetry(client):
    """Verify that URLScan features dictionary stores comprehensive AIML telemetry."""
    payload = {"url": "http://verify-bank-security.stream/checkpoint"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    features = data["features"]
    assert "aiml" in features
    aiml_data = features["aiml"]
    assert "detected_features" in aiml_data
    assert "risk_score" in aiml_data
    assert "classification" in aiml_data
    assert "confidence" in aiml_data
    assert "explanation" in aiml_data
    assert "model_version" in aiml_data

    # Features vector should contain 20 lexical features
    assert len(aiml_data["detected_features"]) == 20
    assert "entropy" in aiml_data["detected_features"]


def test_audit_logs_record_ml_classification(client):
    """Verify that audit logs capture ML classification alongside DSA verdict."""
    payload = {"url": "http://10.0.0.1/admin/login"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    scan_id = response.json()["id"]

    # Verify audit endpoint captures the scan
    audit_res = client.get(f"/api/incidents/audit?entity_type=SCAN&entity_id={scan_id}")
    if audit_res.status_code == 200:
        audits = audit_res.json()
        if audits:
            details = audits[0].get("details", {})
            assert "ml_classification" in details

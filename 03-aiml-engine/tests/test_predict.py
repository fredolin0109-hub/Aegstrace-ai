"""
AEGISTRACE 03-AIML-ENGINE
Unit tests for Prediction Interface, Model Inference, Heuristic Fallback, and Explainable AI.
"""

from pathlib import Path
import pytest

from predict import (
    get_model,
    predict_url,
    fallback_predict,
    generate_explanations,
)
from feature_extraction import extract_features


def test_get_model_loads_successfully():
    """Verify default trained model loads without errors."""
    model, metadata = get_model()
    assert model is not None, "Model failed to load"
    assert metadata is not None, "Metadata failed to load"
    assert "model_type" in metadata
    assert "version" in metadata
    assert metadata["model_type"] == "RandomForestClassifier"


def test_predict_benign_url():
    """Verify inference on legitimate trusted URLs yields SAFE verdict and ALLOW action."""
    benign_url = "https://www.google.com/search?q=cybersecurity+defense"
    result = predict_url(benign_url)

    assert result["url"] == benign_url
    assert isinstance(result["risk_score"], float)
    assert result["risk_score"] < 0.35
    assert result["classification"] == "SAFE"
    assert result["recommended_action"] == "ALLOW"
    assert result["confidence"] >= 0.50
    assert isinstance(result["explanation"], list)
    assert len(result["explanation"]) > 0


def test_predict_phishing_url():
    """Verify inference on overt phishing URL yields HIGH_RISK verdict and BLOCK action."""
    phishing_url = "http://192.168.1.100/login-paypal-verify.php?auth=true&dest=http://attacker.com"
    result = predict_url(phishing_url)

    assert result["url"] == phishing_url
    assert result["risk_score"] >= 0.70
    assert result["classification"] == "HIGH_RISK"
    assert result["recommended_action"] == "BLOCK"
    assert any("IP address" in exp for exp in result["explanation"])


def test_predict_suspicious_url():
    """Verify inference on suspicious greyware URL yields SUSPICIOUS verdict and WARN/INVESTIGATE."""
    suspicious_url = "http://account-update-portal.xyz/billing"
    result = predict_url(suspicious_url)

    assert result["classification"] in ("SUSPICIOUS", "HIGH_RISK")
    assert result["risk_score"] >= 0.35
    assert result["recommended_action"] in ("WARN", "INVESTIGATE", "BLOCK")


def test_fallback_predict_heuristics():
    """Verify deterministic rule-based fallback produces valid scores and bounds."""
    # Clean benign features
    benign_feats = extract_features("https://wikipedia.org/wiki/Computer_science")
    score, conf, cls = fallback_predict(benign_feats)
    assert 0.0 <= score < 0.35
    assert cls == "SAFE"

    # Aggressive phishing features
    phish_feats = extract_features("http://user@192.168.1.1/login-verify-account.xyz//admin")
    score, conf, cls = fallback_predict(phish_feats)
    assert score >= 0.70
    assert cls == "HIGH_RISK"
    assert conf == 0.75


def test_predict_url_with_missing_model_fallback():
    """Verify predict_url gracefully falls back to heuristics when model path is nonexistent."""
    fake_path = Path("non_existent_dir/no_model.joblib")
    result = predict_url("http://192.168.1.1/login.php", model_path=fake_path)

    assert result["model_version"] == "fallback_heuristic"
    assert 0.0 <= result["risk_score"] <= 1.0
    assert result["classification"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK")
    assert any("fallback" in exp for exp in result["explanation"])


def test_generate_explanations_rules():
    """Verify explanation generator returns expected human-readable diagnostic drivers."""
    feats = {
        "is_ip_address": 1,
        "has_at_symbol": 1,
        "is_suspicious_tld": 1,
        "suspicious_keyword_count": 2,
        "has_redirect_token": 1,
        "has_double_slash_path": 1,
        "subdomain_count": 4,
        "hyphen_count_hostname": 3,
        "entropy": 4.8,
        "digit_ratio": 0.3,
        "url_length": 110,
        "is_https": 0,
    }
    exps = generate_explanations(feats, risk_score=0.85)

    assert any("raw IP address" in e for e in exps)
    assert any("@" in e for e in exps)
    assert any("high-abuse top-level domain" in e for e in exps)
    assert any("credential/financial keywords" in e for e in exps)
    assert any("redirect or destination" in e for e in exps)
    assert any("double slashes" in e for e in exps)
    assert any("subdomain nesting" in e for e in exps)
    assert any("Multiple hyphens" in e for e in exps)
    assert any("Shannon entropy" in e for e in exps)
    assert any("High numeric density" in e for e in exps)
    assert any("Anomalously long URL" in e for e in exps)

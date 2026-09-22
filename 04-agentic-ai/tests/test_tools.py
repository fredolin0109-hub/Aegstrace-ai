import pytest
from tools.analyze_url import analyze_url
from tools.threat_lookup import threat_lookup
from tools.domain_check import domain_check
from tools.redirect_check import redirect_check
from tools.create_incident import create_incident
from tools.trigger_uipath import trigger_uipath
from tools.verify_response import verify_response


def test_analyze_url_benign():
    result = analyze_url("https://www.google.com")
    assert result["url"] == "https://www.google.com"
    assert result["classification"] == "SAFE"
    assert result["risk_score"] < 0.35
    assert result["dsa_verdict"] == "SAFE"
    assert "features" in result
    assert result["features"]["is_https"] is True


def test_analyze_url_high_risk():
    result = analyze_url("http://192.168.1.1/paypal-login-security.php")
    assert result["risk_score"] >= 0.70
    assert result["classification"] == "HIGH_RISK"
    assert result["features"]["is_ip_address"] is True
    assert "paypal" in result["features"]["detected_keywords"]


def test_analyze_url_empty_raises_value_error():
    with pytest.raises(ValueError):
        analyze_url("")


def test_threat_lookup_known_safe():
    res = threat_lookup("google.com")
    assert res["category"] == "SAFE"
    assert res["is_known_threat"] is False
    assert res["reputation_score"] == 0.0
    assert len(res["evidence"]) > 0


def test_threat_lookup_known_malicious():
    res = threat_lookup("paypa1.com")
    assert res["category"] == "MALICIOUS"
    assert res["is_known_threat"] is True
    assert res["reputation_score"] >= 0.90
    assert res["threat_type"] == "TYPOSQUATTING"
    assert len(res["evidence"]) > 0


def test_threat_lookup_subdomain_parent_fallback():
    res = threat_lookup("login.secure.paypa1.com")
    assert res["category"] == "MALICIOUS"
    assert res["is_known_threat"] is True
    assert res["threat_type"] == "TYPOSQUATTING"


def test_threat_lookup_unknown():
    res = threat_lookup("unrecorded-sample-company-109283.com")
    assert res["category"] == "UNKNOWN"
    assert res["is_known_threat"] is False


def test_threat_lookup_none_and_empty_safe():
    res = threat_lookup(None)
    assert res["category"] == "UNKNOWN"
    assert res["is_known_threat"] is False

    res_empty = threat_lookup("")
    assert res_empty["category"] == "UNKNOWN"


def test_domain_check_benign():
    res = domain_check("wikipedia.org")
    assert res["is_ip_address"] is False
    assert res["is_suspicious_tld"] is False
    assert res["subdomain_count"] == 0
    assert res["brand_spoof_detected"] is None
    assert res["risk_delta"] == 0.0
    assert res["domain_age_days"] is not None
    assert res["domain_age_days"] > 365
    assert res["is_newly_registered"] is False


def test_domain_check_high_entropy_and_tld():
    res = domain_check("a98b7c6d5e4f3g2h1.xyz")
    assert res["is_high_entropy"] is True
    assert res["is_suspicious_tld"] is True
    assert res["tld"] == "xyz"
    assert res["risk_delta"] > 0.30
    assert len(res["evidence"]) >= 2


def test_domain_check_direct_ip():
    res = domain_check("192.168.1.1")
    assert res["is_ip_address"] is True
    assert res["risk_delta"] >= 0.35
    assert any("Direct IP address" in ev for ev in res["evidence"])


def test_domain_check_brand_spoof():
    res = domain_check("paypal-account-security-update.com")
    assert res["brand_spoof_detected"] == "paypal"
    assert res["risk_delta"] >= 0.30
    assert any("Brand spoofing detected" in ev for ev in res["evidence"])


def test_domain_check_newly_registered_domain():
    res = domain_check("suspect-security-verify.com", domain_age_days=12)
    assert res["domain_age_days"] == 12
    assert res["is_newly_registered"] is True
    assert res["risk_delta"] >= 0.30
    assert any("Newly registered domain" in ev for ev in res["evidence"])


def test_domain_check_homograph_spoof():
    # 'о' is Cyrillic \u043e visually identical to Latin 'o'
    cyrillic_spoof = "g\u043e\u043egle-login.com"
    res = domain_check(cyrillic_spoof)
    assert res["is_homograph_spoof"] is True
    assert res["brand_spoof_detected"] == "google"
    assert res["risk_delta"] >= 0.35
    assert any("Homograph" in ev for ev in res["evidence"])


def test_domain_check_none_and_empty_safe():
    res_none = domain_check(None)
    assert res_none["domain"] == ""
    assert res_none["risk_delta"] == 0.0

    res_empty = domain_check("")
    assert res_empty["domain"] == ""
    assert res_empty["risk_delta"] == 0.0


def test_redirect_check_benign_no_hops():
    res = redirect_check("https://example.com/products/view")
    assert res["has_redirect_loop"] is False
    assert res["hop_count"] == 1
    assert res["is_evasive"] is False
    assert len(res["open_redirect_params"]) == 0


def test_redirect_check_open_redirect_param():
    res = redirect_check("https://portal.com/login?dest=https://malicious-site.xyz/steal")
    assert res["is_evasive"] is True
    assert len(res["open_redirect_params"]) > 0
    assert any("Open redirect parameter" in ev for ev in res["evidence"])


def test_redirect_check_with_cycle():
    chain = ["https://site-b.com", "https://site-c.com", "https://site-a.com"]
    res = redirect_check("https://site-a.com", redirect_chain=chain)
    assert res["has_redirect_loop"] is True
    assert res["is_evasive"] is True
    assert len(res["cycle_nodes"]) >= 2
    assert any("redirect cycle/loop" in ev for ev in res["evidence"])


def test_redirect_check_none_safe():
    res = redirect_check(None)
    assert res["url"] == ""
    assert res["hop_count"] == 0
    assert res["has_redirect_loop"] is False


def test_create_incident_standalone():
    res = create_incident(
        url="http://10.0.0.1/fake-bank.php",
        domain="10.0.0.1",
        risk_score=0.92,
        evidence=["Direct IP hosting", "Bank keyword detected"],
    )
    assert res["created"] is True
    assert res["incident_id"] is not None
    assert res["incident_number"].startswith("INC-")
    assert res["severity"] == "CRITICAL"
    assert res["status"] == "OPEN"
    assert "Phishing Threat Detected: 10.0.0.1" in res["title"]


def test_trigger_uipath_standalone():
    res = trigger_uipath(
        target_url="http://evildomain.xyz/payload",
        incident_id=1234,
        action_type="CONTAIN_HOST",
    )
    assert res["execution_id"].startswith("EXEC-UIPATH-")
    assert res["action_type"] == "CONTAIN_HOST"
    assert res["status"] == "SIMULATED"
    assert res["simulation"] is True
    assert res["details"]["containment_status"] == "ISOLATED"
    assert "ticket_id" in res["details"]


def test_verify_response_standalone():
    uipath_res = trigger_uipath(
        target_url="http://evildomain.xyz/payload",
        incident_id=5678,
        action_type="CONTAIN_HOST",
    )
    verify_res = verify_response(
        execution_id=uipath_res["execution_id"],
        incident_id=5678,
        incident_number="INC-20260922-5678",
        action_type="CONTAIN_HOST",
        uipath_result=uipath_res,
    )
    assert verify_res["verified"] is True
    assert verify_res["execution_status"] == "SIMULATED"
    assert verify_res["containment_status"] == "CONTAINED"
    assert verify_res["ticket_created"] is True
    assert verify_res["ticket_id"] is not None
    assert len(verify_res["checks"]) >= 2
    check_names = [c["check"] for c in verify_res["checks"]]
    assert "HOST_CONTAINMENT" in check_names
    assert "TICKET_GENERATION" in check_names

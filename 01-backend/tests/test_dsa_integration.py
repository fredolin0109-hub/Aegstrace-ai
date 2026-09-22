import pytest


def test_analyze_known_safe_hashmap(client):
    """Verify DSA HashMap O(1) reputation lookup returns SAFE for verified domains."""
    response = client.post("/api/analyze", json={"url": "https://google.com/search?q=cybersecurity"})
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "SAFE"
    assert data["risk_score"] == 0.0
    assert data["dsa_verdict"] == "SAFE"
    assert data["recommendation"] == "ALLOW"
    assert data["graph_summary"] is not None
    assert data["graph_summary"]["total_nodes"] >= 2

    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "KNOWN_LEGITIMATE_DOMAIN" in indicator_types


def test_analyze_known_malicious_typosquatting_hashmap(client):
    """Verify DSA HashMap identifies known malicious typosquatting and escalates to HIGH_RISK."""
    response = client.post("/api/analyze", json={"url": "http://paypa1.com/login-verify"})
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "HIGH_RISK"
    assert data["risk_score"] >= 0.90
    assert data["dsa_verdict"] == "HIGH_RISK"
    assert data["recommendation"] == "BLOCK"

    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "KNOWN_MALICIOUS_DOMAIN" in indicator_types

    mal_ind = next(ind for ind in data["indicators"] if ind["indicator_type"] == "KNOWN_MALICIOUS_DOMAIN")
    assert mal_ind["severity"] == "CRITICAL"
    assert mal_ind["details"]["threat_type"] == "TYPOSQUATTING"


def test_analyze_trie_keyword_multi_match(client):
    """Verify DSA Trie multi-pattern scanner detects deceptive lures and updates indicators."""
    target_url = "http://unknown-host.info/banking-online/metamask-restore/seed-phrase"
    response = client.post("/api/analyze", json={"url": target_url})
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] >= 0.35
    assert data["classification"] in ("SUSPICIOUS", "HIGH_RISK")
    assert data["graph_summary"] is not None
    assert "chain" in data["graph_summary"]

    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert any("TRIE_" in it for it in indicator_types)
    assert "TRIE_FINANCIAL_IMPERSONATION" in indicator_types or "TRIE_CRYPTO_TARGET" in indicator_types


def test_priority_queue_triage_endpoint(client):
    """Verify GET /api/incidents/triage orders incidents via DSA Max-Heap Priority Queue."""
    # 1. Create a LOW priority incident
    res_low = client.post("/api/incidents", json={
        "url": "https://minor-adware.org",
        "title": "Low Priority Adware",
        "description": "Minor adware beaconing observed",
        "severity": "LOW",
    })
    assert res_low.status_code == 201

    # 2. Create a CRITICAL priority incident
    res_crit = client.post("/api/incidents", json={
        "url": "http://ransomware-drop.xyz",
        "title": "Critical Ransomware Deployment",
        "description": "Active C2 beacon and credential exfiltration payload",
        "severity": "CRITICAL",
    })
    assert res_crit.status_code == 201

    # 3. Create a HIGH priority incident
    res_high = client.post("/api/incidents", json={
        "url": "http://paypa1.com/steal-creds",
        "title": "High Risk Credential Harvest",
        "description": "Phishing portal harvesting banking credentials",
        "severity": "HIGH",
    })
    assert res_high.status_code == 201

    # 4. Request triage queue
    triage_res = client.get("/api/incidents/triage")
    assert triage_res.status_code == 200
    triage_data = triage_res.json()

    assert triage_data["total"] >= 3
    items = triage_data["items"]
    # Top incident must be CRITICAL
    assert items[0]["severity"] == "CRITICAL"
    assert items[0]["title"] == "Critical Ransomware Deployment"

    # Second incident must be HIGH
    assert items[1]["severity"] == "HIGH"
    assert items[1]["title"] == "High Risk Credential Harvest"

    # Third incident must be LOW
    assert items[2]["severity"] == "LOW"


def test_incident_search_via_inverted_index(client):
    """Verify incident filtering with DSA Inverted Index full-text search."""
    client.post("/api/incidents", json={
        "url": "https://invoice-scam.xyz",
        "title": "Corporate Wire Transfer Fraud",
        "description": "Urgent CFO wire transfer instruction sent to accounting",
        "severity": "HIGH",
    })
    client.post("/api/incidents", json={
        "url": "https://generic-survey.com",
        "title": "Employee Engagement Survey",
        "description": "Quarterly satisfaction survey sent to all staff",
        "severity": "LOW",
    })

    # Search for "wire transfer"
    res = client.get("/api/incidents?search=wire transfer")
    assert res.status_code == 200
    data = res.json()

    assert data["total"] == 1
    assert "Wire Transfer" in data["items"][0]["title"]


def test_incident_sort_by_priority(client):
    """Verify GET /api/incidents?sort_by=priority orders incidents using Max-Heap."""
    client.post("/api/incidents", json={
        "url": "https://site-a.com",
        "title": "Low Priority Threat",
        "description": "Minor issue",
        "severity": "LOW",
    })
    client.post("/api/incidents", json={
        "url": "https://site-b.com",
        "title": "Critical Phish",
        "description": "Active harvesting",
        "severity": "CRITICAL",
    })

    res = client.get("/api/incidents?sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 2
    assert items[0]["severity"] == "CRITICAL"


def test_incident_sort_by_severity_mergesort(client):
    """Verify GET /api/incidents?sort_by=severity orders incidents via stable MergeSort."""
    client.post("/api/incidents", json={
        "url": "https://site-low.com",
        "title": "Low Priority Adware",
        "description": "Minor adware",
        "severity": "LOW",
    })
    client.post("/api/incidents", json={
        "url": "https://site-med.com",
        "title": "Medium Risk Lure",
        "description": "Suspicious login lure",
        "severity": "MEDIUM",
    })
    client.post("/api/incidents", json={
        "url": "https://site-high.com",
        "title": "High Risk Phish",
        "description": "Credential stealer",
        "severity": "HIGH",
    })
    client.post("/api/incidents", json={
        "url": "https://site-crit.com",
        "title": "Critical Ransomware",
        "description": "C2 beacon",
        "severity": "CRITICAL",
    })

    res = client.get("/api/incidents?sort_by=severity")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 4
    severities = [item["severity"] for item in items]
    assert severities[:4] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_incident_search_and_sort_combined(client):
    """Verify searching with Inverted Index and sorting by priority in combination."""
    client.post("/api/incidents", json={
        "url": "https://paypal-fake1.xyz",
        "title": "PayPal Low Suspicion Notification",
        "description": "Possible spoofed notice",
        "severity": "LOW",
    })
    client.post("/api/incidents", json={
        "url": "https://paypal-fake2.xyz",
        "title": "PayPal Critical Account Lockout Scam",
        "description": "Active credential harvest attacking PayPal users",
        "severity": "CRITICAL",
    })

    res = client.get("/api/incidents?search=paypal&sort_by=priority")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    items = data["items"]
    assert items[0]["severity"] == "CRITICAL"
    assert items[1]["severity"] == "LOW"


def test_analyze_redirect_loop_detection_api(client):
    """Verify ThreatGraph cycle detection via API when redirect chain contains a loop."""
    payload = {
        "url": "http://hop-start.com/redirect",
        "redirect_chain": [
            "http://hop-a.com/landing",
            "http://hop-b.com/forward",
            "http://hop-a.com/landing"
        ]
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["graph_summary"] is not None
    assert data["graph_summary"]["has_redirect_loop"] is True
    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "GRAPH_REDIRECT_LOOP" in indicator_types
    assert data["risk_score"] >= 0.35


def test_analyze_subdomain_fallback_reputation(client):
    """Verify deep subdomains of known safe and malicious domains correctly inherit reputation."""
    # Subdomain of google.com
    res_safe = client.post("/api/analyze", json={"url": "https://accounts.sub.google.com/login"})
    assert res_safe.status_code == 200
    data_safe = res_safe.json()
    assert data_safe["classification"] == "SAFE"
    assert data_safe["risk_score"] == 0.0
    assert "KNOWN_LEGITIMATE_DOMAIN" in [ind["indicator_type"] for ind in data_safe["indicators"]]

    # Subdomain of paypa1.com
    res_mal = client.post("/api/analyze", json={"url": "http://portal.login.paypa1.com/auth"})
    assert res_mal.status_code == 200
    data_mal = res_mal.json()
    assert data_mal["classification"] == "HIGH_RISK"
    assert "KNOWN_MALICIOUS_DOMAIN" in [ind["indicator_type"] for ind in data_mal["indicators"]]

import pytest
from searching import binary_search_domain, binary_search_ip_range, IncidentInvertedIndex


def test_binary_search_domain():
    sorted_domains = [
        "apple.com",
        "google.com",
        "microsoft.com",
        "netflix.com",
        "paypal.com",
        "wikipedia.org",
    ]

    found, idx = binary_search_domain(sorted_domains, "paypal.com")
    assert found is True
    assert idx == 4

    found, idx = binary_search_domain(sorted_domains, "apple.com")
    assert found is True
    assert idx == 0

    found, idx = binary_search_domain(sorted_domains, "notfound.com")
    assert found is False


def test_binary_search_ip_range():
    # IP integer ranges: (start, end, label)
    # 10.0.0.0 to 10.0.0.255 = (167772160, 167772415)
    # 192.168.1.0 to 192.168.1.255 = (3232235776, 3232236031)
    ranges = [
        (167772160, 167772415, "INTERNAL_TEST_BOTNET"),
        (3232235776, 3232236031, "SUSPICIOUS_HOME_RELAY"),
    ]

    match = binary_search_ip_range(ranges, 167772200)
    assert match == "INTERNAL_TEST_BOTNET"

    match_none = binary_search_ip_range(ranges, 2000000000)
    assert match_none is None


def test_incident_inverted_index():
    index = IncidentInvertedIndex()

    index.add_document("INC-1", {
        "title": "PayPal Credential Harvesting Phish",
        "desc": "User redirected to paypal-verify.xyz"
    })
    index.add_document("INC-2", {
        "title": "Microsoft OAuth Token Phish",
        "desc": "Fake signin prompt for Microsoft 365"
    })
    index.add_document("INC-3", {
        "title": "PayPal Fake Invoice Attack",
        "desc": "Billing fraud email directing to download"
    })

    # Single term search
    results = index.search("paypal", mode="OR")
    doc_ids = [r["id"] for r in results]
    assert "INC-1" in doc_ids
    assert "INC-3" in doc_ids
    assert "INC-2" not in doc_ids

    # AND query search
    and_results = index.search("paypal credential", mode="AND")
    assert len(and_results) == 1
    assert and_results[0]["id"] == "INC-1"


def test_incident_inverted_index_url_and_compound_tokens():
    index = IncidentInvertedIndex()
    # Ensure None field doesn't crash and parts of hyphenated URLs match
    index.add_document("INC-URL", {
        "title": "Suspicious login portal",
        "url": "http://evil-banking.com/verify-account",
        "description": None,
    })

    # Search by individual sub-word in URL
    res_banking = index.search("banking")
    assert len(res_banking) == 1
    assert res_banking[0]["id"] == "INC-URL"

    # Search by hyphenated compound
    res_compound = index.search("verify-account")
    assert len(res_compound) == 1
    assert res_compound[0]["id"] == "INC-URL"

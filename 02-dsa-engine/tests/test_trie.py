import pytest
from trie import SuspiciousPatternTrie, create_default_pattern_trie


def test_trie_insert_and_exact_search():
    t = SuspiciousPatternTrie()
    t.insert("banking-login", category="FINANCIAL", severity="HIGH", weight=0.25)

    res = t.exact_search("banking-login")
    assert res is not None
    assert res["pattern"] == "banking-login"
    assert res["category"] == "FINANCIAL"
    assert res["severity"] == "HIGH"

    assert t.exact_search("banking") is None
    assert t.exact_search("login") is None


def test_trie_starts_with():
    t = SuspiciousPatternTrie()
    t.insert("verify-account")
    t.insert("verify-identity")
    t.insert("verify-ssn")
    t.insert("login-secure")

    matches = t.starts_with("verify-")
    assert len(matches) == 3
    assert "verify-account" in matches
    assert "verify-identity" in matches
    assert "verify-ssn" in matches
    assert "login-secure" not in matches


def test_trie_scan_text_substrings():
    t = create_default_pattern_trie()

    url = "https://evil-server.com/secure/paypal-verify/account-update.php?login=true"
    matches = t.scan_text(url)

    patterns_found = [m.pattern for m in matches]
    assert "paypal-verify" in patterns_found
    assert "account-update" in patterns_found
    assert "login" in patterns_found

    # Verify category and severity attributes
    paypal_match = next(m for m in matches if m.pattern == "paypal-verify")
    assert paypal_match.category == "FINANCIAL_IMPERSONATION"
    assert paypal_match.severity == "CRITICAL"

"""
AEGISTRACE 03-AIML-ENGINE
Unit tests for Feature Extraction module (lexical, structural, entropy, and indicators).
"""

import pytest
from feature_extraction import (
    calculate_shannon_entropy,
    clean_and_parse_url,
    extract_features,
    extract_feature_vector,
    FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
)


def test_shannon_entropy_calculation():
    """Verify Shannon entropy computation for edge cases and variable complexity strings."""
    # Empty string has 0 entropy
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy(None) == 0.0

    # Constant repeated character has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0

    # Low entropy vs high entropy
    low_ent = calculate_shannon_entropy("google.com")
    high_ent = calculate_shannon_entropy("a8f9b2c4e1d7g3h5j6k9")
    assert high_ent > low_ent
    assert 0.0 < low_ent < 5.0
    assert high_ent > 4.0


def test_clean_and_parse_url():
    """Verify handling of scheme-less, port-bearing, bracketed IPv6, and standard URLs."""
    # Standard URL
    parsed, cleaned, hostname, is_ip = clean_and_parse_url("https://example.com/path")
    assert parsed.scheme == "https"
    assert hostname == "example.com"
    assert is_ip == 0

    # Scheme-less URL
    parsed, cleaned, hostname, is_ip = clean_and_parse_url("login.paypal.com/signin")
    assert cleaned.startswith("http://")
    assert hostname == "login.paypal.com"
    assert is_ip == 0

    # Raw IPv4 with port
    parsed, cleaned, hostname, is_ip = clean_and_parse_url("http://192.168.1.1:8080/admin")
    assert hostname == "192.168.1.1"
    assert is_ip == 1

    # Bracketed IPv6
    parsed, cleaned, hostname, is_ip = clean_and_parse_url("http://[2001:db8::1]:80/test")
    assert is_ip == 1

    # Empty or degenerate URL
    parsed, cleaned, hostname, is_ip = clean_and_parse_url("")
    assert cleaned == "http://unknown"


def test_feature_names_integrity():
    """Verify that exactly 20 features are defined and match dictionary outputs."""
    assert len(FEATURE_NAMES) == 20
    assert "url_length" in FEATURE_NAMES
    assert "entropy" in FEATURE_NAMES
    assert "is_ip_address" in FEATURE_NAMES
    assert "has_at_symbol" in FEATURE_NAMES
    assert "suspicious_keyword_count" in FEATURE_NAMES


def test_extract_features_benign_url():
    """Verify features extracted from a trusted benign URL."""
    url = "https://www.google.com/search?q=machine+learning"
    feats = extract_features(url)

    assert isinstance(feats, dict)
    assert set(feats.keys()) == set(FEATURE_NAMES)
    assert feats["is_https"] == 1
    assert feats["is_ip_address"] == 0
    assert feats["is_suspicious_tld"] == 0
    assert feats["has_at_symbol"] == 0
    assert feats["has_double_slash_path"] == 0
    assert feats["subdomain_count"] == 1  # 'www'
    assert feats["query_length"] > 0
    assert feats["url_length"] == len(url)


def test_extract_features_phishing_url():
    """Verify features correctly flag phishing characteristics."""
    url = "http://192.168.1.100/login-paypal-verify.php?auth=true&dest=http://portal.com"
    feats = extract_features(url)

    assert feats["is_https"] == 0
    assert feats["is_ip_address"] == 1
    assert feats["suspicious_keyword_count"] >= 3  # login, paypal, verify, auth
    assert feats["has_redirect_token"] == 1  # dest=
    assert feats["digit_count"] >= 7
    assert feats["path_length"] > 0
    assert feats["url_depth"] == 1


def test_extract_features_obfuscation_patterns():
    """Verify detection of @-spoofing, double slashes, and suspicious TLDs."""
    url = "http://victim.com@phish-attacker.xyz//update/wallet"
    feats = extract_features(url)

    assert feats["has_at_symbol"] == 1
    assert feats["has_double_slash_path"] == 1
    assert feats["is_suspicious_tld"] == 1  # .xyz
    assert feats["suspicious_keyword_count"] >= 2  # update, wallet


def test_extract_features_subdomains_and_hyphens():
    """Verify subdomain counting and hostname hyphenation detection."""
    url = "https://secure-login.portal-update.auth.service-verify.com/login"
    feats = extract_features(url)

    assert feats["subdomain_count"] >= 3
    assert feats["hyphen_count_hostname"] >= 3


def test_extract_feature_vector_order_and_types():
    """Verify that extract_feature_vector returns ordered list matching FEATURE_NAMES."""
    url = "https://example.com/test"
    vector = extract_feature_vector(url)

    assert isinstance(vector, list)
    assert len(vector) == len(FEATURE_NAMES)
    for val in vector:
        assert isinstance(val, (int, float))


def test_extract_features_edge_cases():
    """Verify behavior on degenerate inputs (empty, whitespace, none)."""
    for bad_input in ["", "   ", None, 12345]:
        feats = extract_features(bad_input)
        assert isinstance(feats, dict)
        assert len(feats) == len(FEATURE_NAMES)
        assert feats["url_length"] == 0
        assert feats["is_ip_address"] == 0

"""
AEGISTRACE 03-AIML-ENGINE
Feature Extraction Module for Lexical & Structural URL Analysis.
Extracts numerical and categorical-indicator features suitable for machine learning models.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, unquote
from collections import Counter
from typing import Dict, Any, List, Union


# High-abuse Top-Level Domains frequently observed in malicious campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "cam", "fit", "rest", "stream", "live", "link", "guru", "pw", "cc",
    "icu", "site", "vip", "online", "space", "click", "download", "bid",
    "loan", "racing", "date", "review", "country", "win", "party"
}

# High-frequency lure keywords targeted at credentials, auth, and finance
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "security", "banking", "paypal", "account",
    "signin", "wallet", "support", "auth", "confirm", "billing", "password",
    "credential", "recover", "ebay", "appleid", "amazon-security", "service",
    "secure", "free", "bonus", "gift", "token", "airdrop", "metamask",
    "coinbase", "binance", "blockchain", "validate", "suspended", "urgent",
    "checkpoint", "statement", "re-activate", "re-confirm", "passcode"
]

# Patterns representing redirect and forwarding parameters
REDIRECT_TOKENS = [
    "redirect=", "url=", "next=", "dest=", "destination=", "return=",
    "go=", "link=", "r=", "target=", "redir=", "to="
]

# Ordered list of feature names produced by extract_features()
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "subdomain_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "suspicious_keyword_count",
    "is_https",
    "is_ip_address",
    "url_depth",
    "encoded_char_count",
    "is_suspicious_tld",
    "has_redirect_token",
    "has_at_symbol",
    "has_double_slash_path",
    "hyphen_count_hostname",
    "query_length",
    "path_length",
    "entropy",
    "domain_entropy",
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes the Shannon entropy of a string (in bits per symbol).
    Higher entropy indicates higher randomness or obfuscation.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def clean_and_parse_url(url: str):
    """
    Preprocesses URL and handles scheme-less, port-bearing, or bracketed inputs.
    Returns (parsed_result, raw_cleaned_url, hostname, is_ip).
    """
    cleaned = (url or "").strip()
    if not cleaned:
        cleaned = "http://unknown"

    # Prepend default scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception:
        parsed = urlparse("http://invalid.url")

    raw_hostname = (parsed.hostname or "").lower().strip("[]")

    is_ip = 0
    if raw_hostname:
        try:
            ipaddress.ip_address(raw_hostname)
            is_ip = 1
        except ValueError:
            is_ip = 0

    return parsed, cleaned, raw_hostname, is_ip


def extract_features(url: str) -> Dict[str, Union[int, float]]:
    """
    Extracts numerical and binary-flag features from a single URL string.
    Returns a dictionary mapping each feature in FEATURE_NAMES to an int or float.
    """
    if not url or not isinstance(url, str) or not url.strip():
        # Return clean zeroed dictionary for degenerate/empty inputs
        return {name: 0.0 if name in ("entropy", "domain_entropy", "digit_ratio") else 0 for name in FEATURE_NAMES}

    parsed, full_url, hostname, is_ip = clean_and_parse_url(url)
    lower_url = full_url.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Length features
    url_len = len(full_url)
    host_len = len(hostname)
    query_len = len(query)
    path_len = len(path)

    # 2. Subdomain count
    subdomain_count = 0
    if hostname and not is_ip:
        parts = hostname.split(".")
        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # 3. Digit metrics
    digit_count = sum(c.isdigit() for c in full_url)
    digit_ratio = round(digit_count / max(url_len, 1), 4)

    # 4. Special character count
    special_char_count = len(re.findall(r"[-_?=&%@!~+$:;]", full_url))

    # 5. Suspicious keywords count
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

    # 6. Scheme & Protocol
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # 7. URL Depth (number of non-empty path segments)
    path_segments = [p for p in path.split("/") if p]
    url_depth = len(path_segments)

    # 8. Encoded characters (%XX count)
    encoded_char_count = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))

    # 9. TLD evaluation
    tld = hostname.split(".")[-1] if ("." in hostname and not is_ip) else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # 10. Redirect tokens & anomalous slashes
    has_redirect_token = 1 if any(tok in lower_url for tok in REDIRECT_TOKENS) else 0
    has_double_slash_path = 1 if ("//" in path or "//" in unquote(path)) else 0
    has_at_symbol = 1 if "@" in full_url else 0

    # 11. Domain hyphens
    hyphen_count_hostname = hostname.count("-")

    # 12. Information Entropy
    url_entropy = calculate_shannon_entropy(full_url)
    domain_entropy = calculate_shannon_entropy(hostname)

    return {
        "url_length": url_len,
        "hostname_length": host_len,
        "subdomain_count": subdomain_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_count": special_char_count,
        "suspicious_keyword_count": suspicious_keyword_count,
        "is_https": is_https,
        "is_ip_address": is_ip,
        "url_depth": url_depth,
        "encoded_char_count": encoded_char_count,
        "is_suspicious_tld": is_suspicious_tld,
        "has_redirect_token": has_redirect_token,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "hyphen_count_hostname": hyphen_count_hostname,
        "query_length": query_len,
        "path_length": path_len,
        "entropy": url_entropy,
        "domain_entropy": domain_entropy,
    }


def extract_feature_vector(url: str) -> List[Union[int, float]]:
    """Extracts ordered numerical feature vector matching FEATURE_NAMES."""
    feat_dict = extract_features(url)
    return [feat_dict[k] for k in FEATURE_NAMES]

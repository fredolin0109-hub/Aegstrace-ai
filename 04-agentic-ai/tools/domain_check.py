import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from collections import Counter

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "cam", "fit", "rest", "stream", "live", "link", "guru", "cc", "icu",
    "online", "site", "vip", "support", "account", "cyou", "monster"
}

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "chase",
    "wellsfargo", "bankofamerica", "binance", "coinbase", "facebook", "instagram"
]

ESTABLISHED_DOMAINS = {
    "google.com", "wikipedia.org", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "cloudflare.com", "yahoo.com", "bing.com", "linkedin.com",
    "twitter.com", "x.com", "youtube.com", "facebook.com", "instagram.com"
}

HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    '\u0501': 'd', '\u051b': 'q', '\u051d': 'w', '\u03bf': 'o', '\u03b1': 'a',
    '\u03c1': 'p', '\u03bd': 'v', '\u00e0': 'a', '\u00e1': 'a', '\u00e9': 'e',
}


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon information entropy (in bits per symbol) for a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 3)


def normalize_homoglyphs(text: str) -> str:
    """Translates common unicode homoglyphs (Cyrillic, Greek, accented) to ASCII counterparts."""
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def domain_check(
    domain_or_url: Optional[str] = None,
    url: Optional[str] = None,
    domain_age_days: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Inspects deep domain signals including Shannon entropy, domain registration age,
    TLD abuse reputation, lexical structure, raw IP hosting, IDN/punycode homograph attacks,
    and brand impersonation heuristics.
    """
    target = url or domain_or_url
    if not target or not isinstance(target, str) or not target.strip():
        return {
            "domain": "",
            "entropy": 0.0,
            "is_high_entropy": False,
            "domain_age_days": domain_age_days,
            "is_newly_registered": False,
            "tld": "",
            "is_suspicious_tld": False,
            "subdomain_count": 0,
            "hyphen_count": 0,
            "digit_count": 0,
            "is_ip_address": False,
            "brand_spoof_detected": None,
            "is_homograph_spoof": False,
            "risk_delta": 0.0,
            "evidence": [],
        }

    raw = target.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        domain = parsed.hostname or raw
    else:
        domain = raw.split("/")[0].split(":")[0]

    domain_clean = domain.strip().lower()

    # 1. IP Address Check
    is_ip = False
    try:
        ipaddress.ip_address(domain_clean)
        is_ip = True
    except ValueError:
        is_ip = False

    # 2. Entropy
    entropy = calculate_shannon_entropy(domain_clean)
    is_high_entropy = entropy > 3.85

    # 3. TLD Analysis & Subdomain Count
    tld = ""
    is_suspicious_tld = False
    subdomain_count = 0
    hyphen_count = domain_clean.count("-")
    digit_count = sum(c.isdigit() for c in domain_clean)

    if not is_ip and "." in domain_clean:
        parts = domain_clean.split(".")
        tld = parts[-1]
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # 4. Domain Age Analysis & Newly Registered Domain (NRD) Detection
    effective_age_days = domain_age_days
    is_newly_registered = False

    if effective_age_days is None:
        # Check established domains allowlist
        for est in ESTABLISHED_DOMAINS:
            if domain_clean == est or domain_clean.endswith("." + est):
                effective_age_days = 5000  # Well-established domain (>13 years)
                break

    if effective_age_days is not None:
        if effective_age_days < 30:
            is_newly_registered = True
        elif effective_age_days < 90:
            is_newly_registered = False

    # 5. Homograph & Brand Impersonation Check
    brand_spoofed = None
    is_homograph_spoof = False

    # Check for IDN / Punycode
    decoded_domain = domain_clean
    if "xn--" in domain_clean:
        try:
            decoded_domain = domain_clean.encode("ascii").decode("idna")
        except Exception:
            decoded_domain = domain_clean

    transliterated_domain = normalize_homoglyphs(decoded_domain)
    has_unicode_homoglyphs = any(ch in HOMOGLYPH_MAP for ch in decoded_domain) or "xn--" in domain_clean

    if not is_ip:
        for brand in KNOWN_BRANDS:
            legit_domains = [f"{brand}.com", f"{brand}.org", f"{brand}.net"]
            is_legit = any(domain_clean == ld or domain_clean.endswith("." + ld) for ld in legit_domains)

            # Direct substring brand match
            if brand in domain_clean and not is_legit:
                brand_spoofed = brand
                break

            # Homograph brand match (e.g. gооgle or xn--...)
            if brand in transliterated_domain and not is_legit:
                brand_spoofed = brand
                if has_unicode_homoglyphs:
                    is_homograph_spoof = True
                break

    # 6. Risk contribution & evidence generation
    evidence: List[str] = []
    risk_delta = 0.0

    if is_ip:
        risk_delta += 0.35
        evidence.append("Direct IP address host used in place of domain name.")

    if is_newly_registered:
        risk_delta += 0.30
        age_str = f"{effective_age_days} days" if effective_age_days is not None else "< 30 days"
        evidence.append(f"Newly registered domain (age: {age_str} < 30 days) exhibits critical correlation with disposable phishing campaigns.")
    elif effective_age_days is not None and effective_age_days < 90:
        risk_delta += 0.15
        evidence.append(f"Young domain registration (age: {effective_age_days} days < 90 days) warrants elevated monitoring.")

    if is_high_entropy:
        risk_delta += 0.20
        evidence.append(f"High domain character entropy ({entropy:.2f} bits) suggests DGA or randomized lure.")

    if is_suspicious_tld:
        risk_delta += 0.20
        evidence.append(f"High-abuse top-level domain detected: .{tld}.")

    if subdomain_count >= 3:
        risk_delta += 0.15
        evidence.append(f"Excessive nested subdomains detected ({subdomain_count} levels).")

    if hyphen_count >= 2:
        risk_delta += 0.10
        evidence.append(f"Multiple hyphens in domain ({hyphen_count}) indicating possible typosquatting.")

    if is_homograph_spoof:
        risk_delta += 0.35
        evidence.append(f"Homograph / IDN punycode brand spoofing detected: unauthorized visual imitation of '{brand_spoofed}'.")
    elif brand_spoofed:
        risk_delta += 0.30
        evidence.append(f"Brand spoofing detected: unauthorized usage of '{brand_spoofed}' in host '{domain_clean}'.")

    return {
        "domain": domain_clean,
        "entropy": entropy,
        "is_high_entropy": is_high_entropy,
        "domain_age_days": effective_age_days,
        "is_newly_registered": is_newly_registered,
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "is_ip_address": is_ip,
        "brand_spoof_detected": brand_spoofed,
        "is_homograph_spoof": is_homograph_spoof,
        "risk_delta": round(min(0.85, risk_delta), 2),
        "evidence": evidence,
    }

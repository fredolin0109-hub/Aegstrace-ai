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


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon information entropy (in bits per symbol) for a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 3)


def domain_check(
    domain_or_url: str,
    url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Inspects deep domain signals including Shannon entropy, TLD abuse reputation,
    lexical structure, raw IP hosting, and brand impersonation heuristics.
    """
    raw = (url or domain_or_url).strip().lower()
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

    # 3. TLD Analysis
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

    # 4. Brand Spoofing Check
    brand_spoofed = None
    if not is_ip:
        for brand in KNOWN_BRANDS:
            # If brand appears in domain, but domain is not legitimately brand.tld
            if brand in domain_clean:
                legit_domains = [f"{brand}.com", f"{brand}.org", f"{brand}.net"]
                is_legit = any(domain_clean == ld or domain_clean.endswith("." + ld) for ld in legit_domains)
                if not is_legit:
                    brand_spoofed = brand
                    break

    # 5. Risk contribution & evidence generation
    evidence: List[str] = []
    risk_delta = 0.0

    if is_ip:
        risk_delta += 0.35
        evidence.append("Direct IP address host used in place of domain name.")

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

    if brand_spoofed:
        risk_delta += 0.30
        evidence.append(f"Brand spoofing detected: unauthorized usage of '{brand_spoofed}' in host '{domain_clean}'.")

    return {
        "domain": domain_clean,
        "entropy": entropy,
        "is_high_entropy": is_high_entropy,
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "is_ip_address": is_ip,
        "brand_spoof_detected": brand_spoofed,
        "risk_delta": round(min(0.80, risk_delta), 2),
        "evidence": evidence,
    }

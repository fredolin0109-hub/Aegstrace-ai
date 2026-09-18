import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session

from app.models.url_scan import URLScan
from app.models.threat_indicator import ThreatIndicator
from app.services.audit_service import record_audit


SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work", 
    "cam", "fit", "rest", "stream", "live", "link", "guru"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "security", "banking", "paypal", "account",
    "signin", "wallet", "support", "auth", "confirm", "billing", "password",
    "credential", "recover", "ebay", "appleid", "amazon-security"
]


def normalize_url(url: str) -> Tuple[str, str, Optional[str]]:
    """
    Normalizes a given URL, ensures scheme, extracts domain and checks for IP host.
    Returns: (normalized_url, domain, ip_address_or_none)
    """
    url_cleaned = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url_cleaned):
        url_cleaned = "http://" + url_cleaned

    parsed = urlparse(url_cleaned)
    hostname = (parsed.hostname or "").lower()

    # Determine if hostname is a raw IP address
    ip_str = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
        ip_str = str(ip_obj)
    except ValueError:
        ip_str = None

    normalized = parsed.geturl()
    return normalized, hostname, ip_str


def extract_url_features(url: str, domain: str, is_ip: bool) -> Dict[str, Any]:
    """Extract structural and semantic heuristic features from URL."""
    parsed = urlparse(url)
    path = parsed.path or ""
    query = parsed.query or ""
    full_str = url.lower()

    # Subdomain calculation
    subdomain_count = 0
    if not is_ip and domain:
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # Character counts
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = len(re.findall(r"[-_?=&%@]", url))
    has_at_symbol = "@" in url
    has_double_slash_path = "//" in path

    # TLD extraction
    tld = domain.split(".")[-1] if "." in domain and not is_ip else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Keyword search
    detected_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_str]

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "is_ip_address": is_ip,
        "subdomain_count": subdomain_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "is_https": parsed.scheme.lower() == "https",
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "detected_keywords": detected_keywords,
        "path_depth": len([seg for seg in path.split("/") if seg]),
    }


def evaluate_heuristics(features: Dict[str, Any], domain: str) -> Tuple[float, str, float, str, List[Dict[str, Any]]]:
    """
    Evaluates extracted features and returns:
    (risk_score, classification, confidence, recommendation, indicators)
    """
    score = 0.05
    indicators = []

    if features["is_ip_address"]:
        score += 0.35
        indicators.append({
            "indicator_type": "IP_HOST",
            "value": domain,
            "severity": "HIGH",
            "details": {"reason": "Direct IP address host used in place of domain name"}
        })

    if features["has_at_symbol"]:
        score += 0.25
        indicators.append({
            "indicator_type": "URL_OBFUSCATION",
            "value": "@ symbol in URL",
            "severity": "HIGH",
            "details": {"reason": "@ symbol indicates authority spoofing / credential obscuration"}
        })

    if features["is_suspicious_tld"]:
        score += 0.20
        indicators.append({
            "indicator_type": "SUSPICIOUS_TLD",
            "value": features["tld"],
            "severity": "MEDIUM",
            "details": {"reason": f"High-abuse top-level domain '.{features['tld']}'"}
        })

    if features["subdomain_count"] >= 3:
        score += 0.15
        indicators.append({
            "indicator_type": "EXCESSIVE_SUBDOMAINS",
            "value": f"{features['subdomain_count']} subdomains",
            "severity": "MEDIUM",
            "details": {"subdomain_count": features["subdomain_count"]}
        })

    if len(features["detected_keywords"]) > 0:
        increment = min(0.30, len(features["detected_keywords"]) * 0.10)
        score += increment
        indicators.append({
            "indicator_type": "SUSPICIOUS_KEYWORDS",
            "value": ", ".join(features["detected_keywords"]),
            "severity": "HIGH" if len(features["detected_keywords"]) >= 2 else "MEDIUM",
            "details": {"keywords": features["detected_keywords"]}
        })

    if not features["is_https"] and len(features["detected_keywords"]) > 0:
        score += 0.15
        indicators.append({
            "indicator_type": "INSECURE_AUTH_REQUEST",
            "value": "HTTP scheme with credential/login keywords",
            "severity": "HIGH",
            "details": {"scheme": "http"}
        })

    if features["url_length"] > 90:
        score += 0.10
        indicators.append({
            "indicator_type": "ANOMALOUS_LENGTH",
            "value": f"{features['url_length']} characters",
            "severity": "LOW",
            "details": {"length": features["url_length"]}
        })

    # Clamp score
    final_score = round(min(1.0, max(0.0, score)), 2)

    # Classification & recommendation
    if final_score >= 0.70:
        classification = "HIGH_RISK"
        recommendation = "BLOCK"
        confidence = 0.92
    elif final_score >= 0.35:
        classification = "SUSPICIOUS"
        recommendation = "INVESTIGATE"
        confidence = 0.85
    else:
        classification = "SAFE"
        recommendation = "ALLOW"
        confidence = 0.95

    return final_score, classification, confidence, recommendation, indicators


def perform_scan(
    db: Session,
    raw_url: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None
) -> URLScan:
    """Execute complete scan and persist to database."""
    normalized_url, domain, ip_addr = normalize_url(raw_url)
    features = extract_url_features(normalized_url, domain, is_ip=bool(ip_addr))
    risk_score, classification, confidence, recommendation, indicators_data = evaluate_heuristics(features, domain)

    scan = URLScan(
        url=raw_url,
        normalized_url=normalized_url,
        domain=domain,
        ip_address=ip_addr or client_ip,
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        features_json=features,
        recommendation=recommendation,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Save associated threat indicators
    for ind in indicators_data:
        indicator = ThreatIndicator(
            url_scan_id=scan.id,
            indicator_type=ind["indicator_type"],
            value=ind["value"],
            severity=ind["severity"],
            details_json=ind["details"],
        )
        db.add(indicator)

    db.commit()
    db.refresh(scan)

    # Audit log
    record_audit(
        db=db,
        entity_type="SCAN",
        entity_id=str(scan.id),
        action="ANALYZE",
        actor="EXTENSION" if user_agent and "extension" in user_agent.lower() else "SYSTEM",
        details={"url": scan.url, "risk_score": risk_score, "classification": classification},
        ip_address=client_ip,
    )

    return scan

import re
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session

# Ensure 02-dsa-engine and 03-aiml-engine are importable
root_dir = Path(__file__).resolve().parents[3]
dsa_dir = root_dir / "02-dsa-engine"
aiml_dir = root_dir / "03-aiml-engine"
aiml_src = aiml_dir / "src"
threat_dir = root_dir / "05-threat-intelligence"

for p in [dsa_dir, aiml_dir, aiml_src, threat_dir]:
    if str(p) not in sys.path and p.exists():
        sys.path.insert(0, str(p))

from engine import global_dsa_engine, DSAScanResult

try:
    from aggregator import global_threat_aggregator
except ImportError:
    global_threat_aggregator = None

try:
    from predict import predict_url
except ImportError:
    def predict_url(url: str):
        return {
            "url": url,
            "risk_score": 0.05,
            "classification": "SAFE",
            "confidence": 0.50,
            "detected_features": {},
            "explanation": ["ML engine unavailable; using heuristic fallback"],
            "recommended_action": "ALLOW",
            "model_version": "fallback_unavailable",
        }

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


def evaluate_heuristics(
    features: Dict[str, Any],
    domain: str,
    dsa_result: Optional[DSAScanResult] = None,
    ml_result: Optional[Dict[str, Any]] = None,
    threat_intel_report: Optional[Any] = None,
) -> Tuple[float, str, float, str, List[Dict[str, Any]]]:
    """
    Evaluates extracted features and fuses them with 02-dsa-engine algorithmic results,
    03-aiml-engine supervised machine learning predictions, and 05-threat-intelligence
    multi-source aggregator reputation.
    Returns: (risk_score, classification, confidence, recommendation, indicators)
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

    # Integrate DSA Engine results (HashMap reputation, Trie matches, ThreatGraph loop)
    confidence = 0.90
    is_known_safe = False
    if dsa_result:
        # Incorporate DSA detected indicators deduplicating by (type, value)
        existing_keys = {(ind["indicator_type"], ind.get("value", "")) for ind in indicators}
        for dsa_ind in dsa_result.detected_indicators:
            key = (dsa_ind["indicator_type"], dsa_ind.get("value", ""))
            if key not in existing_keys:
                indicators.append(dsa_ind)
                existing_keys.add(key)

        # Domain reputation evaluation
        if dsa_result.known_domain_match:
            dom_category = dsa_result.known_domain_match["category"]
            if dom_category == "SAFE":
                score = 0.0
                confidence = 0.99
                is_known_safe = True
            elif dom_category in ("MALICIOUS", "SUSPICIOUS"):
                score = max(score, dsa_result.dsa_risk_score, 0.90 if dom_category == "MALICIOUS" else 0.50)
                confidence = 0.98 if dom_category == "MALICIOUS" else 0.90
        else:
            # Algorithmic score fusion
            score = max(score, dsa_result.dsa_risk_score)
            confidence = 0.92 if score >= 0.70 else (0.85 if score >= 0.35 else 0.95)

    # Integrate AIML Engine results (Random Forest Probability and Explanations)
    if ml_result:
        ml_score = ml_result.get("risk_score", 0.0)
        ml_cls = ml_result.get("classification", "SAFE")
        ml_conf = ml_result.get("confidence", 0.50)

        # Known safe reputation overrides ML false positives
        if is_known_safe:
            score = 0.0
            confidence = 0.99
        else:
            # Multi-layer score fusion: incorporate supervised probability
            score = max(score, ml_score)
            if ml_cls in ("SUSPICIOUS", "HIGH_RISK"):
                confidence = max(confidence, ml_conf)
                indicators.append({
                    "indicator_type": "AIML_PREDICTION",
                    "value": f"{ml_cls} (risk={ml_score:.2f})",
                    "severity": "HIGH" if ml_cls == "HIGH_RISK" else "MEDIUM",
                    "details": {
                        "ml_risk_score": ml_score,
                        "ml_confidence": ml_conf,
                        "ml_classification": ml_cls,
                        "explanations": ml_result.get("explanation", []),
                        "model_version": ml_result.get("model_version", "1.0.0"),
                    }
                })

    # Integrate Threat Intelligence results (multi-source reputation aggregator)
    if threat_intel_report:
        ti_dict = threat_intel_report.to_dict() if hasattr(threat_intel_report, "to_dict") else threat_intel_report
        ti_score = ti_dict.get("composite_score", 0.0)
        ti_verdict = ti_dict.get("verdict", "SAFE")
        ti_conf = ti_dict.get("confidence", 0.50)

        # Append threat intel indicators deduplicating by (type, value)
        existing_keys = {(ind["indicator_type"], ind.get("value", "")) for ind in indicators}
        for ti_ind in ti_dict.get("indicators", []):
            ti_type = ti_ind.get("type", "THREAT_INTEL")
            source = ti_ind.get("source", "feed")
            details = ti_ind.get("details", {})
            val = f"{source}: {details}" if details else f"Reported by {source}"
            key = (ti_type, val)
            if key not in existing_keys:
                indicators.append({
                    "indicator_type": ti_type,
                    "value": val,
                    "severity": ti_ind.get("severity", "MEDIUM"),
                    "details": details,
                })
                existing_keys.add(key)

        if is_known_safe:
            score = 0.0
            confidence = 0.99
        else:
            score = max(score, ti_score)
            if ti_verdict in ("SUSPICIOUS", "HIGH_RISK"):
                confidence = max(confidence, ti_conf)
                indicators.append({
                    "indicator_type": "THREAT_INTEL_REPUTATION",
                    "value": f"{ti_verdict} (composite_score={ti_score:.2f})",
                    "severity": "HIGH" if ti_verdict == "HIGH_RISK" else "MEDIUM",
                    "details": {
                        "composite_score": ti_score,
                        "verdict": ti_verdict,
                        "confidence": ti_conf,
                        "sources_consulted": ti_dict.get("sources_consulted", []),
                        "sources_available": ti_dict.get("sources_available", []),
                        "cached": ti_dict.get("cached", False),
                    }
                })

    # Clamp score
    final_score = round(min(1.0, max(0.0, score)), 2)

    # Classification & recommendation
    if final_score >= 0.70:
        classification = "HIGH_RISK"
        recommendation = "BLOCK"
    elif final_score >= 0.35:
        classification = "SUSPICIOUS"
        recommendation = "INVESTIGATE"
    else:
        classification = "SAFE"
        recommendation = "ALLOW"

    return final_score, classification, confidence, recommendation, indicators


def perform_scan(
    db: Session,
    raw_url: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    redirect_chain: Optional[List[str]] = None,
) -> URLScan:
    """Execute complete scan and persist to database."""
    normalized_url, domain, ip_addr = normalize_url(raw_url)
    features = extract_url_features(normalized_url, domain, is_ip=bool(ip_addr))

    # Execute DSA Engine Pipeline (HashMap, Trie, ThreatGraph)
    dsa_result: DSAScanResult = global_dsa_engine.analyze_url_dsa(
        raw_url=normalized_url,
        domain=domain,
        ip_address=ip_addr or client_ip,
        redirect_chain=redirect_chain,
    )

    # Execute AIML Engine Pipeline (Feature Extraction + Random Forest Classifier)
    try:
        ml_result = predict_url(normalized_url)
    except Exception as exc:
        ml_result = {
            "url": normalized_url,
            "risk_score": 0.05,
            "classification": "SAFE",
            "confidence": 0.50,
            "detected_features": {},
            "explanation": [f"AIML inference failed: {str(exc)}"],
            "recommended_action": "ALLOW",
            "model_version": "fallback_error",
        }

    # Execute Threat Intelligence Pipeline (VirusTotal, AbuseIPDB, AlienVault, Local DSA)
    threat_intel_report = None
    if global_threat_aggregator:
        try:
            threat_intel_report = global_threat_aggregator.lookup(
                target=normalized_url,
                target_type="url",
            )
        except Exception:
            threat_intel_report = None

    # Attach DSA telemetry to features
    features["dsa"] = dsa_result.to_dict()
    features["dsa_verdict"] = dsa_result.dsa_verdict
    features["dsa_risk_score"] = dsa_result.dsa_risk_score
    features["graph_summary"] = dsa_result.graph_summary
    if dsa_result.known_domain_match:
        features["dsa_reputation"] = dsa_result.known_domain_match["category"]
        features["threat_type"] = dsa_result.known_domain_match["threat_type"]
    if dsa_result.trie_matches:
        features["trie_matched_patterns"] = [m["pattern"] for m in dsa_result.trie_matches]

    # Attach AIML telemetry to features
    features["aiml"] = ml_result
    features["ml_risk_score"] = ml_result.get("risk_score")
    features["ml_classification"] = ml_result.get("classification")
    features["ml_confidence"] = ml_result.get("confidence")
    features["ml_explanations"] = ml_result.get("explanation", [])
    features["ml_model_version"] = ml_result.get("model_version")

    # Attach Threat Intelligence telemetry to features
    if threat_intel_report:
        ti_data = threat_intel_report.to_dict()
        features["threat_intel"] = ti_data
        features["threat_intel_score"] = threat_intel_report.composite_score
        features["threat_intel_verdict"] = threat_intel_report.verdict
        features["threat_intel_sources"] = threat_intel_report.sources_consulted
        features["threat_intel_available"] = threat_intel_report.sources_available
        features["threat_intel_cached"] = threat_intel_report.cached

    risk_score, classification, confidence, recommendation, indicators_data = evaluate_heuristics(
        features=features,
        domain=domain,
        dsa_result=dsa_result,
        ml_result=ml_result,
        threat_intel_report=threat_intel_report,
    )

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

    # Save associated threat indicators (including DSA, AIML & Threat Intel indicators)
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
        details={
            "url": scan.url,
            "risk_score": risk_score,
            "classification": classification,
            "dsa_verdict": dsa_result.dsa_verdict,
            "ml_classification": ml_result.get("classification"),
            "ml_risk_score": ml_result.get("risk_score"),
            "threat_intel_verdict": features.get("threat_intel_verdict"),
            "threat_intel_score": features.get("threat_intel_score"),
        },
        ip_address=client_ip,
    )

    return scan

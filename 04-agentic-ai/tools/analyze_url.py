import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure repo root and submodules are in sys.path
_curr = Path(__file__).resolve()
while _curr.parent != _curr:
    if (_curr / "01-backend").exists() and (_curr / "02-dsa-engine").exists():
        for sub in ["01-backend", "02-dsa-engine", "03-aiml-engine", "03-aiml-engine/src", "04-agentic-ai"]:
            sp = _curr / sub
            if sp.exists() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        break
    _curr = _curr.parent

from engine import global_dsa_engine, DSAScanResult
from predict import predict_url
from app.services.scan_service import normalize_url, extract_url_features, evaluate_heuristics


def analyze_url(
    url: str,
    db: Optional[Any] = None,
    url_scan_id: Optional[int] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    redirect_chain: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Executes fast baseline algorithmic (DSA) and predictive machine learning (AIML)
    threat analysis on the target URL.
    Can run with or without a database session.
    Reuses existing URLScan record if url_scan_id is provided.
    """
    if db is not None:
        try:
            from app.models.url_scan import URLScan
            from app.services.scan_service import perform_scan

            scan = None
            if url_scan_id:
                scan = db.query(URLScan).filter(URLScan.id == url_scan_id).first()

            if not scan:
                scan = perform_scan(
                    db=db,
                    raw_url=url,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    redirect_chain=redirect_chain,
                )

            return {
                "url": scan.url,
                "normalized_url": scan.normalized_url,
                "domain": scan.domain,
                "ip_address": scan.ip_address,
                "risk_score": scan.risk_score,
                "classification": scan.classification,
                "confidence": scan.confidence,
                "recommendation": scan.recommendation,
                "features": scan.features_json or {},
                "dsa_verdict": scan.features_json.get("dsa_verdict", "UNKNOWN"),
                "dsa_risk_score": scan.features_json.get("dsa_risk_score", 0.0),
                "aiml_classification": scan.features_json.get("ml_classification", "UNKNOWN"),
                "aiml_risk_score": scan.features_json.get("ml_risk_score", 0.0),
                "detected_indicators": [
                    {
                        "type": ind.indicator_type,
                        "value": ind.value,
                        "severity": ind.severity,
                        "details": ind.details_json,
                    }
                    for ind in getattr(scan, "indicators", [])
                ],
                "url_scan_id": scan.id,
            }
        except Exception:
            # Fallback to direct computation if DB operation encounters error
            pass

    # Standalone execution (without active DB session)
    normalized_url, domain, ip_addr = normalize_url(url)
    features = extract_url_features(normalized_url, domain, is_ip=bool(ip_addr))

    # DSA Engine analysis
    dsa_result: DSAScanResult = global_dsa_engine.analyze_url_dsa(
        raw_url=normalized_url,
        domain=domain,
        ip_address=ip_addr or client_ip,
        redirect_chain=redirect_chain,
    )

    # AIML Engine analysis
    try:
        ml_result = predict_url(normalized_url)
    except Exception as exc:
        ml_result = {
            "url": normalized_url,
            "risk_score": 0.05,
            "classification": "SAFE",
            "confidence": 0.50,
            "detected_features": {},
            "explanation": [f"AIML fallback: {str(exc)}"],
            "recommended_action": "ALLOW",
            "model_version": "fallback_error",
        }

    # Heuristic & Multimodal score fusion
    risk_score, classification, confidence, recommendation, indicators = evaluate_heuristics(
        features=features,
        domain=domain,
        dsa_result=dsa_result,
        ml_result=ml_result,
    )

    return {
        "url": url,
        "normalized_url": normalized_url,
        "domain": domain,
        "ip_address": ip_addr or client_ip,
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "recommendation": recommendation,
        "features": features,
        "dsa_verdict": dsa_result.dsa_verdict,
        "dsa_risk_score": dsa_result.dsa_risk_score,
        "aiml_classification": ml_result.get("classification", "SAFE"),
        "aiml_risk_score": ml_result.get("risk_score", 0.0),
        "detected_indicators": indicators,
        "url_scan_id": None,
    }

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.scan import ScanRequest, ScanResponse, ThreatIndicatorItem
from app.services.scan_service import perform_scan

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_200_OK, summary="Analyze a URL for phishing and security threats")
def analyze_url(
    payload: ScanRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Ingests a URL, applies fast heuristic analysis and threat indicators,
    and returns risk score, classification, and recommended action.
    """
    if not payload.url or len(payload.url.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Valid URL string is required"
        )

    client_ip = payload.client_ip or (request.client.host if request.client else None)
    user_agent = payload.user_agent or request.headers.get("user-agent")

    try:
        scan = perform_scan(
            db=db,
            raw_url=payload.url,
            client_ip=client_ip,
            user_agent=user_agent,
            redirect_chain=payload.redirect_chain,
        )

        indicators_items = [
            ThreatIndicatorItem(
                indicator_type=ind.indicator_type,
                value=ind.value,
                severity=ind.severity,
                details=ind.details_json or {},
            )
            for ind in scan.threat_indicators
        ]

        dsa_info = scan.features_json.get("dsa", {}) if scan.features_json else {}
        dsa_verdict = (
            scan.features_json.get("dsa_verdict")
            or dsa_info.get("dsa_verdict")
            or dsa_info.get("verdict")
        )
        if scan.features_json and "dsa_risk_score" in scan.features_json:
            dsa_risk_score = scan.features_json["dsa_risk_score"]
        elif "dsa_risk_score" in dsa_info:
            dsa_risk_score = dsa_info["dsa_risk_score"]
        else:
            dsa_risk_score = dsa_info.get("risk_score")

        graph_summary = scan.features_json.get("graph_summary") or dsa_info.get("graph_summary")

        aiml_info = scan.features_json.get("aiml", {}) if scan.features_json else {}
        ml_risk_score = scan.features_json.get("ml_risk_score") if scan.features_json else None
        if ml_risk_score is None and aiml_info:
            ml_risk_score = aiml_info.get("risk_score")

        ml_classification = scan.features_json.get("ml_classification") if scan.features_json else None
        if ml_classification is None and aiml_info:
            ml_classification = aiml_info.get("classification")

        ml_confidence = scan.features_json.get("ml_confidence") if scan.features_json else None
        if ml_confidence is None and aiml_info:
            ml_confidence = aiml_info.get("confidence")

        ml_explanations = scan.features_json.get("ml_explanations") if scan.features_json else None
        if ml_explanations is None and aiml_info:
            ml_explanations = aiml_info.get("explanation")

        return ScanResponse(
            id=scan.id,
            url=scan.url,
            normalized_url=scan.normalized_url,
            domain=scan.domain,
            ip_address=scan.ip_address,
            risk_score=scan.risk_score,
            classification=scan.classification,
            confidence=scan.confidence,
            features=scan.features_json or {},
            recommendation=scan.recommendation,
            indicators=indicators_items,
            dsa_verdict=dsa_verdict,
            dsa_risk_score=dsa_risk_score,
            graph_summary=graph_summary,
            ml_risk_score=ml_risk_score,
            ml_classification=ml_classification,
            ml_confidence=ml_confidence,
            ml_explanations=ml_explanations,
            created_at=scan.created_at,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing URL analysis: {str(e)}"
        )

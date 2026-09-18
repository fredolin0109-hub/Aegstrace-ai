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
            created_at=scan.created_at,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing URL analysis: {str(e)}"
        )

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.dashboard import DashboardStatsResponse, RecentScanItem, RecentIncidentItem
from app.services.stats_service import get_dashboard_stats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse, summary="Get aggregated SOC dashboard metrics")
def dashboard_stats(db: Session = Depends(get_db)):
    """Provides high-level metrics, scan counts, active incident counts, and recent activity."""
    raw_stats = get_dashboard_stats(db=db)

    recent_scans = [
        RecentScanItem(
            id=s.id,
            url=s.url,
            domain=s.domain,
            risk_score=s.risk_score,
            classification=s.classification,
            created_at=s.created_at,
        )
        for s in raw_stats["recent_scans"]
    ]

    recent_incidents = [
        RecentIncidentItem(
            id=i.id,
            incident_number=i.incident_number,
            url=i.url,
            severity=i.severity,
            status=i.status,
            title=i.title,
            created_at=i.created_at,
        )
        for i in raw_stats["recent_incidents"]
    ]

    return DashboardStatsResponse(
        total_scans=raw_stats["total_scans"],
        safe_urls=raw_stats["safe_urls"],
        suspicious_urls=raw_stats["suspicious_urls"],
        high_risk_urls=raw_stats["high_risk_urls"],
        active_incidents=raw_stats["active_incidents"],
        automated_responses=raw_stats["automated_responses"],
        severity_breakdown=raw_stats["severity_breakdown"],
        status_breakdown=raw_stats["status_breakdown"],
        recent_scans=recent_scans,
        recent_incidents=recent_incidents,
    )

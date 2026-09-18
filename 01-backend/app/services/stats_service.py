from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.url_scan import URLScan
from app.models.incident import Incident
from app.models.uipath_action import UiPathAction


def get_dashboard_stats(db: Session) -> Dict[str, Any]:
    """Aggregate high-level SOC statistics and telemetry."""
    total_scans = db.query(URLScan).count()
    safe_urls = db.query(URLScan).filter(URLScan.classification == "SAFE").count()
    suspicious_urls = db.query(URLScan).filter(URLScan.classification == "SUSPICIOUS").count()
    high_risk_urls = db.query(URLScan).filter(URLScan.classification == "HIGH_RISK").count()

    active_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
    automated_responses = db.query(UiPathAction).count()

    # Severity distribution
    severity_rows = db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
    severity_breakdown = {sev: count for sev, count in severity_rows}

    # Status distribution
    status_rows = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    status_breakdown = {st: count for st, count in status_rows}

    # Recent scans
    recent_scans = (
        db.query(URLScan)
        .order_by(desc(URLScan.created_at))
        .limit(5)
        .all()
    )

    # Recent incidents
    recent_incidents = (
        db.query(Incident)
        .order_by(desc(Incident.created_at))
        .limit(5)
        .all()
    )

    return {
        "total_scans": total_scans,
        "safe_urls": safe_urls,
        "suspicious_urls": suspicious_urls,
        "high_risk_urls": high_risk_urls,
        "active_incidents": active_incidents,
        "automated_responses": automated_responses,
        "severity_breakdown": severity_breakdown,
        "status_breakdown": status_breakdown,
        "recent_scans": recent_scans,
        "recent_incidents": recent_incidents,
    }

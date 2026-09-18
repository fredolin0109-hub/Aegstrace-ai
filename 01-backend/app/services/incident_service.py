import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.incident import Incident
from app.models.url_scan import URLScan
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services.audit_service import record_audit


def generate_incident_number() -> str:
    """Generate human-readable unique incident ID (e.g. INC-20260918-A1B2)."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"INC-{date_str}-{short_uuid}"


def create_incident(db: Session, incident_data: IncidentCreate, actor: str = "SYSTEM") -> Incident:
    """Create a new incident and log audit trail."""
    incident_number = generate_incident_number()

    incident = Incident(
        incident_number=incident_number,
        url_scan_id=incident_data.url_scan_id,
        url=incident_data.url,
        severity=incident_data.severity.upper(),
        status="OPEN",
        title=incident_data.title,
        description=incident_data.description,
        assigned_to=incident_data.assigned_to,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    record_audit(
        db=db,
        entity_type="INCIDENT",
        entity_id=str(incident.id),
        action="CREATE",
        actor=actor,
        details={
            "incident_number": incident.incident_number,
            "severity": incident.severity,
            "url": incident.url,
        },
    )

    return incident


def list_incidents(
    db: Session,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[int, List[Incident]]:
    """List incidents with optional filtering and pagination."""
    query = db.query(Incident)

    if status:
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (Incident.title.ilike(search_fmt)) |
            (Incident.url.ilike(search_fmt)) |
            (Incident.incident_number.ilike(search_fmt))
        )

    total = query.count()
    items = query.order_by(desc(Incident.created_at)).offset(skip).limit(limit).all()
    return total, items


def get_incident_by_id(db: Session, incident_id: int) -> Optional[Incident]:
    """Retrieve incident by primary key ID."""
    return db.query(Incident).filter(Incident.id == incident_id).first()


def update_incident(
    db: Session,
    incident_id: int,
    update_data: IncidentUpdate,
    actor: str = "ANALYST"
) -> Optional[Incident]:
    """Update incident status, severity, or assignments."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        return None

    changes = {}
    if update_data.title is not None:
        incident.title = update_data.title
        changes["title"] = update_data.title
    if update_data.description is not None:
        incident.description = update_data.description
        changes["description"] = update_data.description
    if update_data.severity is not None:
        incident.severity = update_data.severity.upper()
        changes["severity"] = incident.severity
    if update_data.assigned_to is not None:
        incident.assigned_to = update_data.assigned_to
        changes["assigned_to"] = update_data.assigned_to
    if update_data.status is not None:
        new_status = update_data.status.upper()
        incident.status = new_status
        changes["status"] = new_status
        if new_status in ("RESOLVED", "FALSE_POSITIVE", "CONTAINED"):
            incident.resolved_at = datetime.now(timezone.utc)
            changes["resolved_at"] = str(incident.resolved_at)

    db.commit()
    db.refresh(incident)

    record_audit(
        db=db,
        entity_type="INCIDENT",
        entity_id=str(incident.id),
        action="UPDATE",
        actor=actor,
        details=changes,
    )

    return incident

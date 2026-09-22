import uuid
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Ensure 02-dsa-engine is importable
dsa_dir = Path(__file__).resolve().parents[3] / "02-dsa-engine"
if str(dsa_dir) not in sys.path and dsa_dir.exists():
    sys.path.insert(0, str(dsa_dir))

from priority_queue import IncidentPriorityQueue, IncidentPriorityItem, SEVERITY_WEIGHTS
from searching import IncidentInvertedIndex
from sorting import mergesort_incidents

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


def triage_incidents(
    db: Session,
    status: Optional[str] = "OPEN",
    limit: int = 50,
) -> List[Incident]:
    """
    SOC Incident Triage powered by 02-dsa-engine IncidentPriorityQueue (Indexed Max-Heap).
    Prioritizes open incidents by composite severity weight + scan risk score in O(N log N).
    """
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status.upper())

    candidates = query.all()
    if not candidates:
        return []

    pq = IncidentPriorityQueue()
    incident_map: Dict[str, Incident] = {}

    for inc in candidates:
        incident_map[str(inc.id)] = inc
        risk = 0.5
        if inc.scan and inc.scan.risk_score is not None:
            risk = inc.scan.risk_score

        pq.push(
            incident_id=str(inc.id),
            title=inc.title,
            severity=inc.severity,
            risk_score=risk,
            metadata={"incident_number": inc.incident_number, "status": inc.status},
        )

    triaged_incidents: List[Incident] = []
    while not pq.is_empty() and len(triaged_incidents) < limit:
        top_item = pq.pop()
        if top_item and top_item.incident_id in incident_map:
            triaged_incidents.append(incident_map[top_item.incident_id])

    return triaged_incidents


def list_incidents(
    db: Session,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[int, List[Incident]]:
    """List incidents with optional filtering, DSA Inverted Index search, and Priority Queue triage."""
    query = db.query(Incident)

    if status:
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())

    # DSA Inverted Index Search integration
    if search and search.strip():
        candidates = query.all()
        if not candidates:
            return 0, []

        inverted_index = IncidentInvertedIndex()
        cand_map: Dict[str, Incident] = {}
        for inc in candidates:
            cand_map[str(inc.id)] = inc
            inverted_index.add_document(
                doc_id=str(inc.id),
                fields={
                    "title": inc.title,
                    "description": inc.description or "",
                    "url": inc.url,
                    "incident_number": inc.incident_number,
                }
            )

        search_results = inverted_index.search(search.strip(), mode="OR")
        matched_ids = [r["id"] for r in search_results]

        if matched_ids:
            matched_incidents = [cand_map[doc_id] for doc_id in matched_ids if doc_id in cand_map]

            if sort_by == "priority":
                pq = IncidentPriorityQueue()
                for inc in matched_incidents:
                    risk = inc.scan.risk_score if (inc.scan and inc.scan.risk_score is not None) else 0.5
                    pq.push(
                        incident_id=str(inc.id),
                        title=inc.title,
                        severity=inc.severity,
                        risk_score=risk,
                    )
                sorted_items = []
                while not pq.is_empty():
                    top = pq.pop()
                    if top and top.incident_id in cand_map:
                        sorted_items.append(cand_map[top.incident_id])
                matched_incidents = sorted_items
            elif sort_by == "severity":
                matched_incidents = mergesort_incidents(
                    matched_incidents,
                    key=lambda inc: SEVERITY_WEIGHTS.get(inc.severity.upper(), 0.0),
                    reverse=True,
                )
            elif sort_by == "recent":
                matched_incidents.sort(key=lambda inc: inc.created_at, reverse=True)

            total = len(matched_incidents)
            return total, matched_incidents[skip:skip + limit]
        else:
            # Fallback SQL ilike
            search_fmt = f"%{search.strip()}%"
            query = query.filter(
                (Incident.title.ilike(search_fmt)) |
                (Incident.url.ilike(search_fmt)) |
                (Incident.incident_number.ilike(search_fmt))
            )

    # Sorting strategies
    if sort_by == "priority":
        # 02-dsa-engine IncidentPriorityQueue (Indexed Max-Heap)
        candidates = query.all()
        pq = IncidentPriorityQueue()
        incident_map = {}
        for inc in candidates:
            incident_map[str(inc.id)] = inc
            risk = inc.scan.risk_score if (inc.scan and inc.scan.risk_score is not None) else 0.5
            pq.push(
                incident_id=str(inc.id),
                title=inc.title,
                severity=inc.severity,
                risk_score=risk,
            )
        sorted_items = []
        while not pq.is_empty():
            top = pq.pop()
            if top and top.incident_id in incident_map:
                sorted_items.append(incident_map[top.incident_id])
        total = len(sorted_items)
        return total, sorted_items[skip:skip + limit]

    elif sort_by == "severity":
        # 02-dsa-engine Stable MergeSort
        candidates = query.all()
        sorted_items = mergesort_incidents(
            candidates,
            key=lambda inc: SEVERITY_WEIGHTS.get(inc.severity.upper(), 0.0),
            reverse=True,
        )
        total = len(sorted_items)
        return total, sorted_items[skip:skip + limit]

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

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentListResponse,
    UiPathActionSummary,
)
from app.services.incident_service import (
    create_incident,
    list_incidents,
    get_incident_by_id,
    update_incident,
    triage_incidents,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED, summary="Create a new security incident")
def new_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db)
):
    """Creates a new incident record and initializes the SOC audit trail."""
    incident = create_incident(db=db, incident_data=payload, actor="ANALYST")
    return IncidentResponse(
        id=incident.id,
        incident_number=incident.incident_number,
        url_scan_id=incident.url_scan_id,
        url=incident.url,
        severity=incident.severity,
        status=incident.status,
        title=incident.title,
        description=incident.description,
        assigned_to=incident.assigned_to,
        resolved_at=incident.resolved_at,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        uipath_actions=[],
    )


@router.get("", response_model=IncidentListResponse, summary="List security incidents with filtering")
def get_incidents(
    status: Optional[str] = Query(None, description="Filter by status: OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    search: Optional[str] = Query(None, description="Search keyword in title, URL, or incident number"),
    sort_by: Optional[str] = Query(None, description="Sort strategy: 'priority' (DSA Priority Queue), 'severity' (Stable MergeSort), or 'recent'"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves paginated incidents matching filter criteria."""
    total, items = list_incidents(
        db=db,
        status=status,
        severity=severity,
        search=search,
        sort_by=sort_by,
        skip=skip,
        limit=limit,
    )

    response_items = []
    for inc in items:
        actions = [
            UiPathActionSummary(
                id=act.id,
                action_type=act.action_type,
                execution_id=act.execution_id,
                status=act.status,
                executed_at=act.executed_at,
                completed_at=act.completed_at,
            )
            for act in inc.uipath_actions
        ]
        response_items.append(
            IncidentResponse(
                id=inc.id,
                incident_number=inc.incident_number,
                url_scan_id=inc.url_scan_id,
                url=inc.url,
                severity=inc.severity,
                status=inc.status,
                title=inc.title,
                description=inc.description,
                assigned_to=inc.assigned_to,
                resolved_at=inc.resolved_at,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                uipath_actions=actions,
            )
        )

    return IncidentListResponse(total=total, items=response_items)


@router.get("/triage", response_model=IncidentListResponse, summary="Triage active incidents using DSA Priority Queue")
def get_triaged_incidents(
    status: Optional[str] = Query("OPEN", description="Filter by status: OPEN, INVESTIGATING"),
    limit: int = Query(20, ge=1, le=100, description="Max incidents to retrieve from priority queue"),
    db: Session = Depends(get_db)
):
    """
    Automated SOC triage powered by 02-dsa-engine IncidentPriorityQueue (Indexed Max-Heap).
    Extracts high-priority threats (Critical severity + elevated threat scores) first.
    """
    items = triage_incidents(db=db, status=status, limit=limit)
    response_items = []
    for inc in items:
        actions = [
            UiPathActionSummary(
                id=act.id,
                action_type=act.action_type,
                execution_id=act.execution_id,
                status=act.status,
                executed_at=act.executed_at,
                completed_at=act.completed_at,
            )
            for act in inc.uipath_actions
        ]
        response_items.append(
            IncidentResponse(
                id=inc.id,
                incident_number=inc.incident_number,
                url_scan_id=inc.url_scan_id,
                url=inc.url,
                severity=inc.severity,
                status=inc.status,
                title=inc.title,
                description=inc.description,
                assigned_to=inc.assigned_to,
                resolved_at=inc.resolved_at,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                uipath_actions=actions,
            )
        )

    return IncidentListResponse(total=len(response_items), items=response_items)


@router.get("/{incident_id}", response_model=IncidentResponse, summary="Get incident details by ID")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """Retrieves detailed incident metadata including associated UiPath RPA actions."""
    inc = get_incident_by_id(db=db, incident_id=incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} was not found"
        )

    actions = [
        UiPathActionSummary(
            id=act.id,
            action_type=act.action_type,
            execution_id=act.execution_id,
            status=act.status,
            executed_at=act.executed_at,
            completed_at=act.completed_at,
        )
        for act in inc.uipath_actions
    ]

    return IncidentResponse(
        id=inc.id,
        incident_number=inc.incident_number,
        url_scan_id=inc.url_scan_id,
        url=inc.url,
        severity=inc.severity,
        status=inc.status,
        title=inc.title,
        description=inc.description,
        assigned_to=inc.assigned_to,
        resolved_at=inc.resolved_at,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        uipath_actions=actions,
    )


@router.patch("/{incident_id}", response_model=IncidentResponse, summary="Update incident status or details")
def update_incident_details(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db)
):
    """Updates status, severity, or assignment for an active incident."""
    inc = update_incident(db=db, incident_id=incident_id, update_data=payload)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} was not found"
        )

    actions = [
        UiPathActionSummary(
            id=act.id,
            action_type=act.action_type,
            execution_id=act.execution_id,
            status=act.status,
            executed_at=act.executed_at,
            completed_at=act.completed_at,
        )
        for act in inc.uipath_actions
    ]

    return IncidentResponse(
        id=inc.id,
        incident_number=inc.incident_number,
        url_scan_id=inc.url_scan_id,
        url=inc.url,
        severity=inc.severity,
        status=inc.status,
        title=inc.title,
        description=inc.description,
        assigned_to=inc.assigned_to,
        resolved_at=inc.resolved_at,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        uipath_actions=actions,
    )

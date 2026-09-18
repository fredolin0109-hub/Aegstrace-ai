from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    url_scan_id: Optional[int] = None
    assigned_to: Optional[str] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    assigned_to: Optional[str] = None


class UiPathActionSummary(BaseModel):
    id: int
    action_type: str
    execution_id: str
    status: str
    executed_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    id: int
    incident_number: str
    url_scan_id: Optional[int] = None
    url: str
    severity: str
    status: str
    title: str
    description: str
    assigned_to: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    uipath_actions: List[UiPathActionSummary] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    total: int
    items: List[IncidentResponse]

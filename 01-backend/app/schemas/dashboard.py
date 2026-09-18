from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class RecentScanItem(BaseModel):
    id: int
    url: str
    domain: str
    risk_score: float
    classification: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RecentIncidentItem(BaseModel):
    id: int
    incident_number: str
    url: str
    severity: str
    status: str
    title: str
    created_at: datetime

    model_config = {"from_attributes": True}


class DashboardStatsResponse(BaseModel):
    total_scans: int = 0
    safe_urls: int = 0
    suspicious_urls: int = 0
    high_risk_urls: int = 0
    active_incidents: int = 0
    automated_responses: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    status_breakdown: Dict[str, int] = Field(default_factory=dict)
    recent_scans: List[RecentScanItem] = Field(default_factory=list)
    recent_incidents: List[RecentIncidentItem] = Field(default_factory=list)

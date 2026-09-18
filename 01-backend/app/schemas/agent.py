from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AgentActionTraceItem(BaseModel):
    action_type: str
    tool_name: str
    tool_input: Dict[str, Any] = Field(default_factory=dict)
    tool_output: Dict[str, Any] = Field(default_factory=dict)
    decision_rationale: str
    status: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"from_attributes": True}


class InvestigateRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    url_scan_id: Optional[int] = None
    depth: str = Field("standard", description="standard or deep")
    force_escalate: bool = False


class InvestigateResponse(BaseModel):
    url: str
    url_scan_id: Optional[int] = None
    initial_risk_score: float
    final_risk_score: float
    classification: str
    decision: str  # SAFE_PASS, MONITOR, ESCALATE_INCIDENT, TRIGGER_AUTOMATED_RESPONSE
    incident_created: bool = False
    incident_id: Optional[int] = None
    incident_number: Optional[str] = None
    evidence_collected: List[str] = Field(default_factory=list)
    action_trace: List[AgentActionTraceItem] = Field(default_factory=list)
    recommended_action: str

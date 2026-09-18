from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class UiPathTriggerRequest(BaseModel):
    incident_id: int = Field(..., description="ID of incident triggering RPA response")
    action_type: str = Field(
        ...,
        description="Action type: CREATE_TICKET, CONTAIN_HOST, NOTIFY_SOC, ISOLATE_USER, GENERATE_REPORT, BLOCK_DOMAIN"
    )
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary parameters forwarded to UiPath workflow")


class UiPathActionResponse(BaseModel):
    id: int
    incident_id: int
    action_type: str
    execution_id: str
    status: str  # PENDING, RUNNING, SUCCESS, FAILED, SIMULATED
    input_payload: Dict[str, Any] = Field(default_factory=dict)
    result_payload: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class UiPathStatusResponse(BaseModel):
    execution_id: str
    incident_id: int
    action_type: str
    status: str
    progress_percentage: int
    executed_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    is_simulation: bool = True

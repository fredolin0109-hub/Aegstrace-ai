"""
AEGISTRACE Risk Alert & UiPath Integration Schemas
Pydantic validation schemas for risk alerts, UiPath webhooks, and retry actions.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class RiskAlertRequest(BaseModel):
    url: str = Field(..., description="Target URL analyzed for phishing / threat risk")
    risk_score: int = Field(..., ge=0, le=100, description="Composite threat risk score (0-100)")
    classification: str = Field(..., description="Threat classification, e.g. HIGH_RISK, SUSPICIOUS, SAFE")
    reasons: List[str] = Field(default_factory=list, description="List of detected threat indicators / rationale")
    incident_id: Optional[str] = Field(None, description="Optional existing incident identifier (e.g. INC-001)")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        return v


class RiskAlertResponse(BaseModel):
    success: bool
    risk_level: str  # HIGH, MEDIUM, LOW
    incident_id: str
    uipath_status: str  # TRIGGERED, SKIPPED, FAILED, SIMULATED
    email_status: str   # QUEUED, SENT, TEST_MODE_LOGGED, SKIPPED, FAILED
    execution_id: Optional[str] = None
    message: Optional[str] = None


class UiPathCallbackRequest(BaseModel):
    incident_id: str = Field(..., description="Incident number or ID")
    execution_id: str = Field(..., description="UiPath execution task ID")
    status: str = Field(..., description="Execution outcome: COMPLETED, FAILED, RUNNING")
    email_status: Optional[str] = Field(None, description="Email delivery state: SENT, FAILED, QUEUED, SKIPPED")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of callback event")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary execution telemetry")
    error_message: Optional[str] = Field(None, description="Error reason if execution failed")


class UiPathCallbackResponse(BaseModel):
    success: bool
    incident_id: str
    execution_id: str
    updated_status: str
    message: Optional[str] = None


class RetryAlertRequest(BaseModel):
    incident_id: str = Field(..., description="Incident identifier to retry")
    retry_type: str = Field("ALL", description="Target action to retry: UIPATH, EMAIL, or ALL")

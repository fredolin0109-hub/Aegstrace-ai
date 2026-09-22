from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ThreatIndicatorItem(BaseModel):
    indicator_type: str
    value: str
    severity: str
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect", min_length=3, max_length=2048)
    client_ip: Optional[str] = Field(None, description="Client IP address making request")
    user_agent: Optional[str] = Field(None, description="Client user agent string")
    redirect_chain: Optional[List[str]] = Field(None, description="Observed redirect hops for loop detection")


class ScanResponse(BaseModel):
    id: int
    url: str
    normalized_url: str
    domain: str
    ip_address: Optional[str] = None
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Normalized threat risk score between 0 and 1")
    classification: str = Field(..., description="SAFE, SUSPICIOUS, or HIGH_RISK")
    confidence: float = Field(..., ge=0.0, le=1.0)
    features: Dict[str, Any] = Field(default_factory=dict)
    recommendation: str = Field(..., description="ALLOW, WARN, BLOCK, or INVESTIGATE")
    indicators: List[ThreatIndicatorItem] = Field(default_factory=list)
    dsa_verdict: Optional[str] = Field(None, description="Verdict from 02-dsa-engine pipeline (SAFE, SUSPICIOUS, HIGH_RISK)")
    dsa_risk_score: Optional[float] = Field(None, description="Threat score computed by 02-dsa-engine")
    graph_summary: Optional[Dict[str, Any]] = Field(None, description="ThreatGraph topology summary and cycle detection")
    created_at: datetime

    model_config = {"from_attributes": True}

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ThreatIntelLookupResponse(BaseModel):
    target: str = Field(..., description="Queried domain, IP, or URL")
    target_type: str = Field(..., description="Target category: domain, ip, or url")
    composite_score: float = Field(..., ge=0.0, le=1.0, description="Composite risk reputation score")
    verdict: str = Field(..., description="Reputation verdict: SAFE, SUSPICIOUS, or HIGH_RISK")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence level")
    sources_consulted: List[str] = Field(default_factory=list, description="All threat intelligence providers evaluated")
    sources_available: List[str] = Field(default_factory=list, description="Active and configured providers")
    sources_cached: List[str] = Field(default_factory=list, description="Active providers whose results were served from cache")
    cached: bool = Field(False, description="True if response was served from TTL in-memory cache")
    indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted threat indicators")
    provider_details: Dict[str, Any] = Field(default_factory=dict, description="Raw and normalized outputs from each provider")
    domain_info: Optional[Dict[str, Any]] = Field(None, description="DNS and domain metadata")
    timestamp: str = Field(..., description="Lookup completion timestamp")

    model_config = {"from_attributes": True}

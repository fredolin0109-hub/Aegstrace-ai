import sys
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Query, HTTPException, status

# Ensure 05-threat-intelligence is importable
root_dir = Path(__file__).resolve().parents[3]
threat_intel_dir = root_dir / "05-threat-intelligence"
if threat_intel_dir.exists() and str(threat_intel_dir) not in sys.path:
    sys.path.insert(0, str(threat_intel_dir))

from aggregator import global_threat_aggregator
from app.schemas.threat_intel import ThreatIntelLookupResponse

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get(
    "/lookup",
    response_model=ThreatIntelLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query multi-source threat intelligence with caching",
)
def lookup_threat_intelligence(
    target: str = Query(..., min_length=1, description="Target domain, IP, or URL to inspect"),
    target_type: Optional[str] = Query(None, description="Optional target type ('domain', 'ip', 'url')"),
    refresh: bool = Query(False, description="Bypass cache and force upstream refresh"),
):
    """
    Queries VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, and 02-dsa-engine
    with LRU TTL in-memory caching and graceful zero-credential fallback.
    """
    cleaned_target = target.strip()
    if not cleaned_target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target cannot be empty"
        )

    try:
        report = global_threat_aggregator.lookup(
            target=cleaned_target,
            target_type=target_type,
            force_refresh=refresh,
        )
        return ThreatIntelLookupResponse(
            target=report.target,
            target_type=report.target_type,
            composite_score=report.composite_score,
            verdict=report.verdict,
            confidence=report.confidence,
            sources_consulted=report.sources_consulted,
            sources_available=report.sources_available,
            cached=report.cached,
            indicators=report.indicators,
            provider_details=report.provider_details,
            domain_info=report.domain_info,
            timestamp=report.timestamp,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat intelligence lookup failed: {str(exc)}"
        )


@router.get(
    "/stats",
    status_code=status.HTTP_200_OK,
    summary="Retrieve threat intelligence cache and provider telemetry",
)
def get_threat_intel_stats():
    """Returns cache diagnostic metrics and configured provider status."""
    return {
        "cache_stats": global_threat_aggregator.cache_stats(),
        "available_sources": global_threat_aggregator.get_available_sources(),
    }

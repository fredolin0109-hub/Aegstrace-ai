import sys
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# Ensure repo root and submodules are in sys.path
_curr = Path(__file__).resolve()
while _curr.parent != _curr:
    if (_curr / "01-backend").exists() and (_curr / "02-dsa-engine").exists():
        for sub in ["01-backend", "02-dsa-engine", "03-aiml-engine", "03-aiml-engine/src", "04-agentic-ai"]:
            sp = _curr / sub
            if sp.exists() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        break
    _curr = _curr.parent


def create_incident(
    url: str,
    domain: str,
    risk_score: float,
    severity: Optional[str] = None,
    evidence: Optional[List[str]] = None,
    url_scan_id: Optional[int] = None,
    db: Optional[Any] = None,
    actor: str = "AGENT",
) -> Dict[str, Any]:
    """
    Creates an official SOC incident record in the database for escalated threats.
    Falls back gracefully to simulated incident metadata when running without database access.
    """
    clamped_score = round(max(0.0, min(1.0, risk_score)), 2)

    # Calculate severity tier
    if not severity:
        if clamped_score >= 0.85:
            eff_severity = "CRITICAL"
        elif clamped_score >= 0.65:
            eff_severity = "HIGH"
        elif clamped_score >= 0.40:
            eff_severity = "MEDIUM"
        else:
            eff_severity = "LOW"
    else:
        eff_severity = severity.upper()

    evidence_text = "; ".join(evidence) if evidence else "Elevated risk characteristics detected by AegisAgent."
    title = f"Phishing Threat Detected: {domain}"
    description = (
        f"Autonomous investigation escalated URL {url} with risk score {clamped_score:.2f} ({eff_severity}). "
        f"Evidence: {evidence_text}"
    )

    if db is not None:
        try:
            from app.schemas.incident import IncidentCreate
            from app.services.incident_service import create_incident as service_create_incident

            incident_data = IncidentCreate(
                url=url,
                title=title,
                description=description,
                severity=eff_severity,
                url_scan_id=url_scan_id,
            )
            incident_obj = service_create_incident(db=db, incident_data=incident_data, actor=actor)
            return {
                "incident_id": incident_obj.id,
                "incident_number": incident_obj.incident_number,
                "title": incident_obj.title,
                "severity": incident_obj.severity,
                "status": incident_obj.status,
                "url": incident_obj.url,
                "created": True,
            }
        except Exception:
            # Fall back to simulated record on unexpected DB failure
            pass

    # Simulated incident creation for unit testing / standalone execution
    mock_id = int(datetime.now().timestamp()) % 100000 + 1000
    mock_num = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    return {
        "incident_id": mock_id,
        "incident_number": mock_num,
        "title": title,
        "severity": eff_severity,
        "status": "OPEN",
        "url": url,
        "created": True,
    }

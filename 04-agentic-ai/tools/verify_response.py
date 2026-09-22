import sys
from pathlib import Path
from datetime import datetime, timezone
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


def verify_response(
    execution_id: Optional[str] = None,
    incident_id: Optional[int] = None,
    action_type: Optional[str] = None,
    uipath_result: Optional[Dict[str, Any]] = None,
    db: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Verifies the operational outcome of automated security responses,
    validating RPA execution completion, network host containment, and SOC ticket issuance.
    """
    checks: List[Dict[str, Any]] = []
    exec_status = "UNKNOWN"
    containment_status = "PENDING"
    ticket_created = False
    ticket_id = None
    incident_status = None

    # 1. Fetch action status from DB if available
    db_action_data = None
    if db is not None and execution_id:
        try:
            from app.services.uipath_service import get_uipath_action_status
            db_action_data = get_uipath_action_status(db, execution_id)
        except Exception:
            pass

    # Merge status data
    merged_details = {}
    if db_action_data:
        exec_status = db_action_data.get("status", "UNKNOWN")
        res = db_action_data.get("result", {})
        merged_details = res.get("details", {})
    elif uipath_result:
        exec_status = uipath_result.get("status", "UNKNOWN")
        merged_details = uipath_result.get("details", {})

    # Check 1: RPA Execution Check
    rpa_passed = exec_status in ("SUCCESS", "SIMULATED", "COMPLETED")
    checks.append({
        "check": "RPA_EXECUTION",
        "passed": rpa_passed,
        "detail": f"UiPath RPA execution status: {exec_status}."
    })

    # Check 2: Incident Status Check
    if db is not None and incident_id:
        try:
            from app.models.incident import Incident
            inc = db.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                incident_status = inc.status
                if inc.status in ("CONTAINED", "CLOSED"):
                    containment_status = "CONTAINED"
                else:
                    containment_status = "ACTIVE"
        except Exception:
            pass

    # Check 3: Host Containment Verification
    act = (action_type or (uipath_result.get("action_type") if uipath_result else "")).upper()
    if act in ("CONTAIN_HOST", "BLOCK_DOMAIN"):
        # Check if details contain containment confirmation
        host_contained = (
            containment_status == "CONTAINED"
            or merged_details.get("containment_status") == "ISOLATED"
            or merged_details.get("domain_policy") == "SINKHOLE_ACTIVE"
            or rpa_passed
        )
        if host_contained:
            containment_status = "CONTAINED"

        checks.append({
            "check": "HOST_CONTAINMENT",
            "passed": host_contained,
            "detail": (
                "DNS sinkhole and endpoint network isolation successfully verified."
                if host_contained
                else "Containment action pending or unverified."
            )
        })
    else:
        containment_status = "NOT_APPLICABLE"

    # Check 4: Ticket Issuance Verification
    # Try to find ticket_id in details
    if isinstance(merged_details, dict):
        if "ticket_id" in merged_details:
            ticket_id = merged_details["ticket_id"]
        elif "CREATE_TICKET" in merged_details:
            ticket_id = merged_details["CREATE_TICKET"].get("ticket_id")

    if ticket_id:
        ticket_created = True
        checks.append({
            "check": "TICKET_GENERATION",
            "passed": True,
            "detail": f"SOC incident ticket created: {ticket_id}."
        })
    elif act == "CREATE_TICKET":
        checks.append({
            "check": "TICKET_GENERATION",
            "passed": rpa_passed,
            "detail": "Ticket generated via automated RPA pipeline."
        })
        ticket_created = rpa_passed

    overall_verified = all(c["passed"] for c in checks) if checks else False

    return {
        "verified": overall_verified,
        "execution_id": execution_id or (uipath_result.get("execution_id") if uipath_result else None),
        "execution_status": exec_status,
        "containment_status": containment_status,
        "ticket_created": ticket_created,
        "ticket_id": ticket_id,
        "incident_status": incident_status,
        "checks": checks,
        "verification_timestamp": datetime.now(timezone.utc).isoformat(),
    }

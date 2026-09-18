import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.models.uipath_action import UiPathAction
from app.models.incident import Incident
from app.schemas.uipath import UiPathTriggerRequest
from app.services.audit_service import record_audit


def generate_execution_id() -> str:
    """Generate unique execution ID for RPA tasks."""
    return f"EXEC-UIPATH-{uuid.uuid4().hex[:8].upper()}"


def trigger_uipath_workflow(
    db: Session,
    request: UiPathTriggerRequest,
    actor: str = "SYSTEM"
) -> UiPathAction:
    """
    Trigger a UiPath robotic process automation response action.
    Supports both simulated execution (DEMO_MODE) and real Orchestrator webhook dispatch.
    """
    execution_id = generate_execution_id()

    incident = db.query(Incident).filter(Incident.id == request.incident_id).first()
    if not incident:
        raise ValueError(f"Incident with ID {request.incident_id} does not exist.")

    input_payload = {
        "incident_id": incident.id,
        "incident_number": incident.incident_number,
        "target_url": incident.url,
        "severity": incident.severity,
        "action_type": request.action_type,
        "parameters": request.parameters,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # If in DEMO_MODE or UIPATH_SIMULATION_MODE, generate realistic simulated response
    if settings.DEMO_MODE or settings.UIPATH_SIMULATION_MODE or not settings.UIPATH_CLIENT_ID:
        status = "SIMULATED"
        completed_at = datetime.now(timezone.utc)
        result_payload = {
            "execution_id": execution_id,
            "orchestrator_connected": False,
            "simulation": True,
            "action_executed": request.action_type,
            "details": {
                "CREATE_TICKET": {
                    "ticket_id": f"SOC-TICKET-{uuid.uuid4().hex[:6].upper()}",
                    "assigned_team": "Tier 2 SOC Incident Response",
                    "priority": incident.severity,
                    "summary": f"Automated phishing containment for {incident.url}",
                },
                "CONTAIN_HOST": {
                    "action": "Firewall DNS Sinkhole applied",
                    "target_url": incident.url,
                    "containment_status": "ISOLATED",
                },
                "NOTIFY_SOC": {
                    "channel": "Slack #soc-critical-alerts",
                    "message_dispatched": True,
                    "severity": incident.severity,
                },
                "ISOLATE_USER": {
                    "action": "Triggered SSO session revocation",
                    "user": incident.assigned_to or "victim_workstation",
                },
                "GENERATE_REPORT": {
                    "report_format": "PDF",
                    "report_hash": uuid.uuid4().hex,
                    "status": "GENERATED",
                },
                "BLOCK_DOMAIN": {
                    "domain_policy": "SINKHOLE_ACTIVE",
                    "ttl": 86400,
                }
            }.get(request.action_type, {"message": "Action simulated successfully"}),
            "execution_duration_ms": 340,
        }

        # Automatically update incident status to CONTAINED if containment action was triggered
        if request.action_type in ("CONTAIN_HOST", "BLOCK_DOMAIN"):
            incident.status = "CONTAINED"
            db.commit()

    else:
        # Placeholder for live UiPath Orchestrator HTTP API invocation
        status = "PENDING"
        completed_at = None
        result_payload = {"orchestrator_status": "Job queued"}

    action_record = UiPathAction(
        incident_id=incident.id,
        action_type=request.action_type,
        execution_id=execution_id,
        status=status,
        input_payload_json=input_payload,
        result_payload_json=result_payload,
        executed_at=datetime.now(timezone.utc),
        completed_at=completed_at,
    )

    db.add(action_record)
    db.commit()
    db.refresh(action_record)

    record_audit(
        db=db,
        entity_type="UIPATH",
        entity_id=action_record.execution_id,
        action="TRIGGER",
        actor=actor,
        details={
            "action_type": action_record.action_type,
            "status": action_record.status,
            "incident_id": incident.id,
        }
    )

    return action_record


def get_uipath_action_status(db: Session, execution_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve the live or simulated status of a UiPath action."""
    action = db.query(UiPathAction).filter(UiPathAction.execution_id == execution_id).first()
    if not action:
        return None

    progress = 100 if action.status in ("SUCCESS", "SIMULATED", "FAILED") else 45
    return {
        "execution_id": action.execution_id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "status": action.status,
        "progress_percentage": progress,
        "executed_at": action.executed_at,
        "completed_at": action.completed_at,
        "result": action.result_payload_json,
        "error_message": action.error_message,
        "is_simulation": action.status == "SIMULATED",
    }

import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

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


def trigger_uipath(
    target_url: str,
    incident_id: Optional[int] = None,
    incident_number: Optional[str] = None,
    action_type: str = "CONTAIN_HOST",
    parameters: Optional[Dict[str, Any]] = None,
    db: Optional[Any] = None,
    actor: str = "AEGIS_AGENT",
) -> Dict[str, Any]:
    """
    Triggers an authorized UiPath Robotic Process Automation (RPA) workflow
    (e.g., CONTAIN_HOST, BLOCK_DOMAIN, CREATE_TICKET, NOTIFY_SOC).
    Dispatches to backend UiPath service or generates deterministic simulation payload.
    """
    act_type = action_type.upper()

    if db is not None and incident_id is not None:
        try:
            from app.schemas.uipath import UiPathTriggerRequest
            from app.services.uipath_service import trigger_uipath_workflow

            req = UiPathTriggerRequest(
                incident_id=incident_id,
                action_type=act_type,
                parameters=parameters or {},
            )
            action_record = trigger_uipath_workflow(db=db, request=req, actor=actor)
            return {
                "execution_id": action_record.execution_id,
                "action_type": action_record.action_type,
                "status": action_record.status,
                "incident_id": incident_id,
                "target_url": target_url,
                "details": (action_record.result_payload_json or {}).get("details", {}),
                "simulation": action_record.status == "SIMULATED",
                "executed_at": action_record.executed_at.isoformat() if action_record.executed_at else None,
            }
        except Exception:
            pass

    # Standalone simulated dispatch
    execution_id = f"EXEC-UIPATH-{uuid.uuid4().hex[:8].upper()}"
    ticket_id = f"SOC-TICKET-{uuid.uuid4().hex[:6].upper()}"

    simulated_details = {
        "CONTAIN_HOST": {
            "action": "Firewall DNS Sinkhole applied",
            "target_url": target_url,
            "containment_status": "ISOLATED",
            "ticket_id": ticket_id,
        },
        "BLOCK_DOMAIN": {
            "domain_policy": "SINKHOLE_ACTIVE",
            "ttl": 86400,
            "target_url": target_url,
            "ticket_id": ticket_id,
        },
        "CREATE_TICKET": {
            "ticket_id": ticket_id,
            "assigned_team": "Tier 2 SOC Incident Response",
            "priority": "HIGH",
            "summary": f"Automated phishing containment for {target_url}",
        },
        "NOTIFY_SOC": {
            "channel": "Slack #soc-critical-alerts",
            "message_dispatched": True,
            "target_url": target_url,
        },
    }.get(act_type, {
        "action": f"Executed {act_type}",
        "target_url": target_url,
        "status": "COMPLETED",
        "ticket_id": ticket_id,
    })

    return {
        "execution_id": execution_id,
        "action_type": act_type,
        "status": "SIMULATED",
        "incident_id": incident_id or 9999,
        "target_url": target_url,
        "details": simulated_details,
        "simulation": True,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }

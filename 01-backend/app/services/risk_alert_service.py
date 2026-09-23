"""
AEGISTRACE Risk Alert & Automation Service
Orchestrates risk level categorization, incident creation/updating, UiPath RPA dispatch,
email alerting, and immutable audit tracking.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.models.incident import Incident
from app.models.uipath_action import UiPathAction
from app.models.threat_indicator import ThreatIndicator
from app.schemas.risk_alert import (
    RiskAlertRequest,
    RiskAlertResponse,
    UiPathCallbackRequest,
    UiPathCallbackResponse,
    RetryAlertRequest,
)
from app.services.email_service import send_risk_alert_email
from app.services.audit_service import record_audit
from app.services.incident_service import generate_incident_number


def determine_risk_level(risk_score: int) -> str:
    """Categorizes numerical risk score into LOW, MEDIUM, or HIGH tiers."""
    if risk_score >= settings.RISK_HIGH_THRESHOLD:
        return "HIGH"
    elif risk_score >= settings.RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def get_or_create_incident(
    db: Session,
    url: str,
    risk_score: int,
    risk_level: str,
    classification: str,
    reasons: list,
    preferred_id: Optional[str] = None,
) -> Incident:
    """Locates an existing incident or constructs a new high-fidelity incident record."""
    incident = None
    if preferred_id:
        # Search by incident_number or numeric id
        incident = db.query(Incident).filter(Incident.incident_number == preferred_id).first()
        if not incident and preferred_id.isdigit():
            incident = db.query(Incident).filter(Incident.id == int(preferred_id)).first()

    if not incident:
        inc_number = preferred_id if (preferred_id and preferred_id.startswith("INC-")) else generate_incident_number()
        severity_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        severity = severity_map.get(risk_level, "MEDIUM")

        title = f"Automated Risk Detection: {url[:70]}"
        desc_lines = [
            f"Risk Score: {risk_score}% ({risk_level})",
            f"Classification: {classification}",
            "Detected Indicators:",
        ]
        for r in reasons:
            desc_lines.append(f" - {r}")

        incident = Incident(
            incident_number=inc_number,
            url=url,
            severity=severity,
            status="OPEN",
            title=title,
            description="\n".join(desc_lines),
            assigned_to="AUTOMATED_SOC_TIER1",
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        record_audit(
            db=db,
            entity_type="INCIDENT",
            entity_id=str(incident.id),
            action="CREATE_FROM_RISK_ALERT",
            actor="AUTOMATION_ENGINE",
            details={
                "incident_number": incident.incident_number,
                "url": url,
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
        )

        # Attach threat indicators
        for reason in reasons:
            ind = ThreatIndicator(
                incident_id=incident.id,
                indicator_type="URL_HEURISTIC",
                value=str(reason)[:255],
                severity=severity,
                details_json={"source": "RISK_ALERT_PIPELINE"},
            )
            db.add(ind)
        db.commit()

    return incident


def process_risk_alert(db: Session, payload: RiskAlertRequest) -> RiskAlertResponse:
    """
    Main risk alert intake pipeline:
    1. Determine risk tier (HIGH, MEDIUM, LOW)
    2. Retrieve or create incident
    3. Idempotency check
    4. Trigger UiPath RPA and/or email alert based on risk tier
    5. Write audit logs and return automation status
    """
    risk_level = determine_risk_level(payload.risk_score)
    incident = get_or_create_incident(
        db=db,
        url=payload.url,
        risk_score=payload.risk_score,
        risk_level=risk_level,
        classification=payload.classification,
        reasons=payload.reasons,
        preferred_id=payload.incident_id,
    )

    # Idempotency check: check if an identical alert ran within the last 5 minutes
    existing_action = (
        db.query(UiPathAction)
        .filter(
            UiPathAction.incident_id == incident.id,
            UiPathAction.alert_type == "RISK_ALERT",
        )
        .order_by(UiPathAction.executed_at.desc())
        .first()
    )

    if existing_action:
        age_seconds = (datetime.now(timezone.utc) - existing_action.executed_at.replace(tzinfo=timezone.utc)).total_seconds()
        if age_seconds < 300:  # 5 minutes window
            return RiskAlertResponse(
                success=True,
                risk_level=risk_level,
                incident_id=incident.incident_number,
                uipath_status=existing_action.status,
                email_status=existing_action.email_status or "SKIPPED",
                execution_id=existing_action.execution_id,
                message=f"Duplicate alert suppressed by idempotency policy. Active execution: {existing_action.execution_id}",
            )

    execution_id = f"UIPATH-{uuid.uuid4().hex[:10].upper()}"
    timestamp_str = datetime.now(timezone.utc).isoformat()

    # Branch 1: HIGH RISK (70-100) -> Trigger UiPath + Send Priority Email
    if risk_level == "HIGH":
        incident.severity = "HIGH"
        db.commit()

        # Step A: Dispatch / log email alert
        email_result = send_risk_alert_email(
            risk_level="HIGH",
            incident_id=incident.incident_number,
            url=payload.url,
            risk_score=payload.risk_score,
            classification=payload.classification,
            reasons=payload.reasons,
            recipient_email=settings.ALERT_EMAIL,
            timestamp=timestamp_str,
        )
        email_status = email_result.get("status", "QUEUED")

        # Step B: Record UiPath action
        status_val = "SUCCESS" if (settings.DEMO_MODE or settings.UIPATH_SIMULATION_MODE) else "PENDING"
        uipath_action = UiPathAction(
            incident_id=incident.id,
            action_type="NOTIFY_SOC",
            execution_id=execution_id,
            status=status_val,
            email_status=email_status,
            alert_type="RISK_ALERT",
            input_payload_json={
                "incident_id": incident.id,
                "incident_number": incident.incident_number,
                "url": payload.url,
                "risk_score": payload.risk_score,
                "risk_level": "HIGH",
                "classification": payload.classification,
                "reasons": payload.reasons,
                "recipient_email": settings.ALERT_EMAIL,
            },
            result_payload_json={
                "workflow": "AEGISTRACE_RiskAlert",
                "email_delivery": email_result,
                "status": status_val,
            },
            executed_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc) if status_val == "SUCCESS" else None,
        )
        db.add(uipath_action)
        db.commit()
        db.refresh(uipath_action)

        # Step C: Record full audit timeline
        record_audit(
            db=db,
            entity_type="UIPATH",
            entity_id=execution_id,
            action="TRIGGER_RISK_ALERT",
            actor="AUTOMATION_ENGINE",
            details={
                "incident_id": incident.id,
                "incident_number": incident.incident_number,
                "action_type": "NOTIFY_SOC",
                "workflow": "AEGISTRACE_RiskAlert",
                "email_status": email_status,
                "recipient": settings.ALERT_EMAIL,
            },
        )

        return RiskAlertResponse(
            success=True,
            risk_level="HIGH",
            incident_id=incident.incident_number,
            uipath_status="TRIGGERED",
            email_status=email_status,
            execution_id=execution_id,
            message="High-risk incident processed; UiPath workflow triggered and security alert email queued.",
        )

    # Branch 2: MEDIUM RISK (30-69) -> Create/Update Incident, Optional Email, No Aggressive RPA
    elif risk_level == "MEDIUM":
        incident.severity = "MEDIUM"
        db.commit()

        email_status = "SKIPPED"
        if settings.MEDIUM_RISK_EMAIL_ENABLED:
            email_result = send_risk_alert_email(
                risk_level="MEDIUM",
                incident_id=incident.incident_number,
                url=payload.url,
                risk_score=payload.risk_score,
                classification=payload.classification,
                reasons=payload.reasons,
                recipient_email=settings.ALERT_EMAIL,
                timestamp=timestamp_str,
            )
            email_status = email_result.get("status", "QUEUED")

        record_audit(
            db=db,
            entity_type="INCIDENT",
            entity_id=str(incident.id),
            action="MEDIUM_RISK_RECORDED",
            actor="AUTOMATION_ENGINE",
            details={
                "incident_number": incident.incident_number,
                "risk_score": payload.risk_score,
                "email_status": email_status,
            },
        )

        return RiskAlertResponse(
            success=True,
            risk_level="MEDIUM",
            incident_id=incident.incident_number,
            uipath_status="SKIPPED",
            email_status=email_status,
            execution_id=None,
            message="Medium-risk incident logged for SOC review; high-priority automation not escalated.",
        )

    # Branch 3: LOW RISK (0-29) -> Record only, No Email, No UiPath
    else:
        record_audit(
            db=db,
            entity_type="INCIDENT",
            entity_id=str(incident.id),
            action="LOW_RISK_RECORDED",
            actor="AUTOMATION_ENGINE",
            details={
                "incident_number": incident.incident_number,
                "risk_score": payload.risk_score,
                "url": payload.url,
            },
        )

        return RiskAlertResponse(
            success=True,
            risk_level="LOW",
            incident_id=incident.incident_number,
            uipath_status="SKIPPED",
            email_status="SKIPPED",
            execution_id=None,
            message="Low-risk assessment. No incident escalation or email alert required.",
        )


def process_uipath_callback(db: Session, payload: UiPathCallbackRequest) -> UiPathCallbackResponse:
    """
    Handles confirmation callbacks from UiPath robots or Orchestrator webhook.
    Updates uipath_actions, audit_logs, and incidents.
    """
    action = db.query(UiPathAction).filter(UiPathAction.execution_id == payload.execution_id).first()
    if not action:
        # Fallback search by incident_number
        inc = db.query(Incident).filter(Incident.incident_number == payload.incident_id).first()
        if inc:
            action = db.query(UiPathAction).filter(UiPathAction.incident_id == inc.id).order_by(UiPathAction.executed_at.desc()).first()

    if not action:
        raise ValueError(f"UiPath execution ID '{payload.execution_id}' not found.")

    # Update action record
    action.status = payload.status.upper()
    if payload.email_status:
        action.email_status = payload.email_status.upper()
    if payload.error_message:
        action.error_message = payload.error_message
    if action.status in ("COMPLETED", "SUCCESS", "FAILED"):
        action.completed_at = datetime.now(timezone.utc)

    # Merge details into result payload
    existing_result = action.result_payload_json or {}
    if payload.details:
        existing_result.update(payload.details)
    action.result_payload_json = existing_result

    # Update incident status if completed
    incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
    if incident and action.status in ("COMPLETED", "SUCCESS"):
        if incident.status == "OPEN":
            incident.status = "INVESTIGATING"
        incident.updated_at = datetime.now(timezone.utc)

    db.commit()

    # Record callback in immutable audit logs
    record_audit(
        db=db,
        entity_type="UIPATH",
        entity_id=payload.execution_id,
        action="CALLBACK_RECEIVED",
        actor="UIPATH_ROBOT",
        details={
            "incident_id": payload.incident_id,
            "status": payload.status,
            "email_status": payload.email_status,
            "error_message": payload.error_message,
        },
    )

    return UiPathCallbackResponse(
        success=True,
        incident_id=payload.incident_id,
        execution_id=payload.execution_id,
        updated_status=action.status,
        message="UiPath execution and email statuses recorded successfully.",
    )


def retry_incident_automation(db: Session, payload: RetryAlertRequest) -> Dict[str, Any]:
    """
    Safe retry mechanism for failed or unconfirmed UiPath RPA or Email executions.
    """
    inc = db.query(Incident).filter(Incident.incident_number == payload.incident_id).first()
    if not inc and payload.incident_id.isdigit():
        inc = db.query(Incident).filter(Incident.id == int(payload.incident_id)).first()

    if not inc:
        raise ValueError(f"Incident '{payload.incident_id}' not found for retry.")

    execution_id = f"UIPATH-RETRY-{uuid.uuid4().hex[:8].upper()}"
    uipath_status = "SKIPPED"
    email_status = "SKIPPED"

    retry_type = payload.retry_type.upper()

    if retry_type in ("EMAIL", "ALL"):
        email_res = send_risk_alert_email(
            risk_level="HIGH" if inc.severity == "HIGH" else "MEDIUM",
            incident_id=inc.incident_number,
            url=inc.url,
            risk_score=90 if inc.severity == "HIGH" else 50,
            classification=inc.severity,
            reasons=["Manual operator automated retry triggered"],
            recipient_email=settings.ALERT_EMAIL,
        )
        email_status = email_res.get("status", "QUEUED")

    if retry_type in ("UIPATH", "ALL"):
        uipath_status = "TRIGGERED"
        new_action = UiPathAction(
            incident_id=inc.id,
            action_type="NOTIFY_SOC",
            execution_id=execution_id,
            status="SUCCESS" if (settings.DEMO_MODE or settings.UIPATH_SIMULATION_MODE) else "PENDING",
            email_status=email_status,
            alert_type="RETRY_ALERT",
            input_payload_json={"retry": True, "incident_number": inc.incident_number},
            result_payload_json={"retry_type": retry_type, "triggered_at": datetime.now(timezone.utc).isoformat()},
            executed_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(new_action)

    db.commit()

    record_audit(
        db=db,
        entity_type="UIPATH",
        entity_id=execution_id,
        action=f"RETRY_{retry_type}",
        actor="SOC_ANALYST",
        details={
            "incident_id": inc.id,
            "incident_number": inc.incident_number,
            "retry_type": retry_type,
            "email_status": email_status,
            "uipath_status": uipath_status,
        },
    )

    return {
        "success": True,
        "incident_id": inc.incident_number,
        "execution_id": execution_id,
        "uipath_status": uipath_status,
        "email_status": email_status,
        "message": f"Automation retry for {retry_type} executed successfully.",
    }

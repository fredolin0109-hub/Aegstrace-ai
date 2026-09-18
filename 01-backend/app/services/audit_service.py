from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog


def record_audit(
    db: Session,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str = "SYSTEM",
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """Write an immutable entry to audit_logs."""
    log_entry = AuditLog(
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        actor=actor,
        details_json=details or {},
        ip_address=ip_address,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

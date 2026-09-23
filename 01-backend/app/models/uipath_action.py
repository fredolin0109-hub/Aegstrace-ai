from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class UiPathAction(Base):
    __tablename__ = "uipath_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(64), nullable=False)  # CREATE_TICKET, CONTAIN_HOST, NOTIFY_SOC, ISOLATE_USER, GENERATE_REPORT, BLOCK_DOMAIN
    execution_id = Column(String(128), unique=True, index=True, nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")  # PENDING, RUNNING, SUCCESS, FAILED, SIMULATED
    input_payload_json = Column(JSON, nullable=False, default=dict)
    result_payload_json = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    email_status = Column(String(32), nullable=True, default=None)  # QUEUED, SENT, FAILED, SKIPPED, TEST_MODE_LOGGED
    alert_type = Column(String(64), nullable=True, default=None)    # RISK_ALERT, MANUAL_DISPATCH, RETRY_ALERT
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="uipath_actions")

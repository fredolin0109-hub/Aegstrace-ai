from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class AgentAction(Base):
    __tablename__ = "agent_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url_scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    action_type = Column(String(64), nullable=False)  # DETECT, INVESTIGATE, DECIDE, ESCALATE, VERIFY
    tool_name = Column(String(128), nullable=False)
    tool_input_json = Column(JSON, nullable=False, default=dict)
    tool_output_json = Column(JSON, nullable=False, default=dict)
    decision_rationale = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="SUCCESS")  # SUCCESS, FAILED, RUNNING
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("URLScan", back_populates="agent_actions")
    incident = relationship("Incident", back_populates="agent_actions")

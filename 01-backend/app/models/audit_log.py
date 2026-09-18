from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    entity_type = Column(String(64), nullable=False, index=True)  # SCAN, INCIDENT, UIPATH, AGENT, CONFIG
    entity_id = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)                    # CREATE, UPDATE, TRIGGER, INVESTIGATE, RESOLVE
    actor = Column(String(64), nullable=False, default="SYSTEM")   # SYSTEM, AGENT, ANALYST, UIPATH_RPA, EXTENSION
    details_json = Column(JSON, nullable=False, default=dict)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

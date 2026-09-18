from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_number = Column(String(64), unique=True, index=True, nullable=False)
    url_scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="SET NULL"), nullable=True)
    url = Column(String(2048), nullable=False)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), nullable=False, default="OPEN")      # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    assigned_to = Column(String(128), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("URLScan", back_populates="incidents")
    threat_indicators = relationship("ThreatIndicator", back_populates="incident", cascade="all, delete-orphan")
    agent_actions = relationship("AgentAction", back_populates="incident", cascade="all, delete-orphan")
    uipath_actions = relationship("UiPathAction", back_populates="incident", cascade="all, delete-orphan")

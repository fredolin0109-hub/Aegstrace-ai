from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    normalized_url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    classification = Column(String(32), nullable=False, default="SAFE")  # SAFE, SUSPICIOUS, HIGH_RISK
    confidence = Column(Float, nullable=False, default=1.0)
    features_json = Column(JSON, nullable=False, default=dict)
    recommendation = Column(String(64), nullable=False, default="ALLOW")  # ALLOW, WARN, BLOCK, INVESTIGATE
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    incidents = relationship("Incident", back_populates="scan", cascade="all, delete-orphan")
    threat_indicators = relationship("ThreatIndicator", back_populates="scan", cascade="all, delete-orphan")
    agent_actions = relationship("AgentAction", back_populates="scan", cascade="all, delete-orphan")

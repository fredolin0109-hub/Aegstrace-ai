from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url_scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    indicator_type = Column(String(64), nullable=False)  # TYPOSQUATTING, SUSPICIOUS_TLD, IP_HOST, etc.
    value = Column(String(512), nullable=False)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    details_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("URLScan", back_populates="threat_indicators")
    incident = relationship("Incident", back_populates="threat_indicators")

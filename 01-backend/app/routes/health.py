from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.config import settings

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", summary="Check system health and database connectivity")
def health_check(db: Session = Depends(get_db)):
    """Returns application status, database connectivity, and runtime settings."""
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": "AEGISTRACE Backend API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_status,
        "demo_mode": settings.DEMO_MODE,
        "environment": settings.ENV,
    }

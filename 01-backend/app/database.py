import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# Ensure sqlite directory exists if using default relative sqlite path
if settings.DATABASE_URL.startswith("sqlite"):
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=settings.DEBUG and settings.ENV == "development",
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables on application startup and perform forward column migrations."""
    import app.models  # noqa: F401 - ensure models are imported before create_all
    Base.metadata.create_all(bind=engine)

    # Safe schema migration for SQLite: add email_status and alert_type if missing
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "uipath_actions" in inspector.get_table_names():
            columns = [c["name"] for c in inspector.get_columns("uipath_actions")]
            with engine.connect() as conn:
                if "email_status" not in columns:
                    conn.execute(text("ALTER TABLE uipath_actions ADD COLUMN email_status VARCHAR(32)"))
                if "alert_type" not in columns:
                    conn.execute(text("ALTER TABLE uipath_actions ADD COLUMN alert_type VARCHAR(64)"))
                conn.commit()
    except Exception as exc:
        print(f"[AEGISTRACE DB] Migration check notice: {exc}")

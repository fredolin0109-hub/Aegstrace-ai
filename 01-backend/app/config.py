import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENV: str = "development"
    DEBUG: bool = True
    DEMO_MODE: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./database/aegistrace.db"

    # API Configuration
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    API_PREFIX: str = "/api"

    # CORS Origins (comma separated string parsed to list)
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173,chrome-extension://*"

    # Threat Intelligence Keys (Optional)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # UiPath RPA Configuration
    UIPATH_ORCHESTRATOR_URL: str = "https://cloud.uipath.com"
    UIPATH_ORGANIZATION_UNIT: str = ""
    UIPATH_TENANT_NAME: str = ""
    UIPATH_CLIENT_ID: str = ""
    UIPATH_USER_KEY: str = ""
    UIPATH_PROCESS_NAME: str = "AegisTrace_PhishingResponse"
    UIPATH_SIMULATION_MODE: bool = True
    UIPATH_TEST_MODE: bool = True

    # Email Alert Configuration
    ALERT_EMAIL: str = "security-admin@example.com"
    EMAIL_TEST_MODE: bool = True
    MEDIUM_RISK_EMAIL_ENABLED: bool = False
    SMTP_HOST: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "aegistrace-alerts@example.com"
    SMTP_USE_TLS: bool = True

    # Risk Thresholds
    RISK_HIGH_THRESHOLD: int = 70
    RISK_MEDIUM_THRESHOLD: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        if not self.CORS_ORIGINS:
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "TraceForensics"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "traceforensics-super-secret-jwt-key-change-in-production-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./traceforensics.db")

    # Storage
    EVIDENCE_STORAGE_DIR: str = os.getenv("EVIDENCE_STORAGE_DIR", "./storage/evidence")
    REPORT_STORAGE_DIR: str = os.getenv("REPORT_STORAGE_DIR", "./storage/reports")

    # Threat Intel
    ENABLE_EXTERNAL_THREAT_INTEL: bool = os.getenv("ENABLE_EXTERNAL_THREAT_INTEL", "false").lower() == "true"
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    model_config = SettingsConfigDict(case_sensitive=True)


settings = Settings()

"""
app/core/config.py
Centralised settings — all values read from environment variables / .env file.
"""
from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "Domain Impersonation Monitoring Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str = "changeme"

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://dimp:dimp_pass@localhost:5432/dimp"
    database_url_sync: str = "postgresql+psycopg2://dimp:dimp_pass@localhost:5432/dimp"

    # ── Redis / Celery ────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # ── Auth ──────────────────────────────────────────────────────────────────
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # ── Scanning ──────────────────────────────────────────────────────────────
    screenshot_dir: str = "/app/data/screenshots"
    report_dir: str = "/app/data/reports"
    max_concurrent_scans: int = 10
    http_timeout: int = 15
    http_user_agent: str = "DIMP-Scanner/1.0 (security research)"

    # ── Threat intelligence API keys (optional) ───────────────────────────────
    urlscan_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""

    # ── Alerting ──────────────────────────────────────────────────────────────
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "alerts@yourdomain.com"
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    siem_webhook_url: str = ""

    # ── CORS ──────────────────────────────────────────────────────────────────
    allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: str) -> str:
        return v  # kept as raw string; parsed where needed

    def get_allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

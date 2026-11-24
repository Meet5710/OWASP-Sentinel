"""OWASP Sentinel - Application Settings and Configuration

Reads configuration from environment variables and provides validated runtime settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import (
    ALLOWED_SCHEMES,
    DEFAULT_SCHEME,
    MAX_URL_LENGTH,
)


class Settings(BaseSettings):
    """Application runtime settings backed by environment variables."""

    PROJECT_NAME: str = "OWASP Sentinel"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    APP_ENV: str = "development"
    DEBUG: bool = True

    # Network bindings
    HOST: str = "127.0.0.1"
    PORT: int = 8001

    # Input validation & SSRF security defaults
    ALLOWED_SCHEMES: tuple[str, ...] = ALLOWED_SCHEMES
    DEFAULT_SCHEME: str = DEFAULT_SCHEME
    MAX_TARGET_URL_LENGTH: int = MAX_URL_LENGTH
    ALLOW_PRIVATE_IPS_DEFAULT: bool = False
    DEFAULT_REQUEST_TIMEOUT_SECONDS: int = 10
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60

    # Database connection string (defaults to local SQLite for Phase 1-2)
    DATABASE_URL: str = "sqlite:///./sentinel.db"

    # Redis state store and task queue broker
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS origins for frontend React dashboard
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

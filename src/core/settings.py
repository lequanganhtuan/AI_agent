from __future__ import annotations

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized runtime configuration for the entire application.

    Responsibilities
    ----------------
    - Load environment variables from .env
    - Validate required configuration
    - Expose immutable application settings

    Notes
    -----
    This is the ONLY place in the project that should access
    environment variables directly.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )


    # Application
    app_name: str = "AI URL Fraud Detection System"

    environment: str = Field(
        default="development",
        alias="ENVIRONMENT",
    )

    debug: bool = Field(
        default=False,
        alias="DEBUG",
    )


    # VirusTotal
    virustotal_api_key: str = Field(
        alias="VIRUSTOTAL_API_KEY",
    )

    # Google Safe Browsing (https://console.cloud.google.com/apis/credentials?project=movie-382714)
    google_safe_browsing_api_key: str = Field(
        alias="GOOGLE_SAFE_BROWSING_API_KEY",
    )

    # URLScan (https://urlscan.io/user/profile/)
    urlscan_api_key: str = Field(
        alias="URLSCAN_API_KEY",
    )

    # URLHaus (https://urlhaus.abuse.ch/)
    urlhaus_api_key: str = Field(
        alias="URLHAUS_API_KEY",
    )

    # AbuseIPDB (https://www.abuseipdb.com/account/api/keys)
    abuseipdb_api_key: str = Field(
        alias="ABUSEIPDB_API_KEY",
    )

    # OpenAI (Future Phase)
    openai_api_key: str | None = Field(
        default=None,
        alias="OPENAI_API_KEY",
    )

    # Gemini (Phase 5)
    gemini_api_key: str | None = Field(
        default=None,
        alias="GEMINI_API_KEY",
    )


    # Redis (Future Phase)
    redis_url: str | None = Field(
        default=None,
        alias="REDIS_URL",
    )

    # PostgreSQL (Future Phase)
    database_url: str | None = Field(
        default=None,
        alias="DATABASE_URL",
    )

    # Firestore (Phase 6)
    firestore_project_id: str | None = Field(
        default=None,
        alias="FIRESTORE_PROJECT_ID",
    )

    google_application_credentials: str | None = Field(
        default=None,
        alias="GOOGLE_APPLICATION_CREDENTIALS",
    )


settings = Settings()

if settings.google_application_credentials:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials
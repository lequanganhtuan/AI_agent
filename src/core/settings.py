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

    firestore_database_id: str | None = Field(
        default=None,
        alias="FIRESTORE_DATABASE_ID",
    )

    cache_ttl: int = Field(
        default=86400,
        alias="CACHE_TTL",
    )

    gemini_model_name: str = Field(
        default="gemini-2.5-flash-lite",
        alias="GEMINI_MODEL_NAME",
    )

    gemini_backup_model_name: str = Field(
        default="gemini-2.5-flash",
        alias="GEMINI_BACKUP_MODEL_NAME",
    )

    gemini_timeout: float = Field(
        default=60.0,
        alias="GEMINI_TIMEOUT",
    )

    firestore_collection_name: str = Field(
        default="scans",
        alias="FIRESTORE_COLLECTION_NAME",
    )

    agent_max_retries: int = Field(
        default=3,
        alias="AGENT_MAX_RETRIES",
    )

    safe_whitelist_domains: str = Field(
        default="google.com,gmail.com,youtube.com,facebook.com,apple.com,microsoft.com,live.com,outlook.com,twitter.com,x.com,linkedin.com,netflix.com,wikipedia.org,amazon.com,github.com,cloudflare.com,abuse.ch,virustotal.com,google.com.vn,googlevideo.com,example.com",
        alias="SAFE_WHITELIST_DOMAINS",
    )

    firestore_ttl: int = Field(
        default=2592000,
        alias="FIRESTORE_TTL",
    )

    agent_api_key: str | None = Field(
        default=None,
        alias="AGENT_API_KEY",
    )

    @property
    def whitelist_domains_set(self) -> set[str]:
        return {d.strip().lower() for d in self.safe_whitelist_domains.split(",") if d.strip()}


settings = Settings()

if settings.google_application_credentials:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials
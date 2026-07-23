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



    # PostgreSQL (Future Phase)
    database_url: str | None = Field(
        default=None,
        alias="DATABASE_URL",
    )

    # Firestore (Phase 6)
    firestore_project_id: str | None = Field(
        default="vtrust-vn",
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
        default=7200,
        alias="CACHE_TTL",
    )

    gemini_model_name: str = Field(
        default="gemini-2.5-flash",
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
        default="""
            google.com
            gmail.com
            youtube.com
            googlevideo.com
            apple.com
            icloud.com
            microsoft.com
            live.com
            outlook.com
            office.com
            microsoftonline.com
            amazon.com
            aws.amazon.com
            cloudflare.com
            facebook.com
            fb.com
            messenger.com
            instagram.com
            twitter.com
            x.com
            linkedin.com
            tiktok.com
            reddit.com
            pinterest.com
            tumblr.com
            discord.com
            telegram.org
            whatsapp.com
            zoom.us
            skype.com
            github.com
            githubusercontent.com
            gitlab.com
            bitbucket.org
            docker.com
            npmjs.com
            pypi.org
            stackoverflow.com
            stackexchange.com
            medium.com
            dev.to
            vercel.app
            netlify.app
            supabase.com
            firebase.com
            render.com
            fly.dev
            railway.app
            heroku.com
            openai.com
            chatgpt.com
            anthropic.com
            claude.ai
            cohere.com
            huggingface.co
            replicate.com
            groq.com
            perplexity.ai
            abuse.ch
            virustotal.com
            shodan.io
            censys.io
            talosintelligence.com
            urlscan.io
            alienvault.com
            haveibeenpwned.com
            snyk.io
            owasp.org
            stripe.com
            paypal.com
            visa.com
            mastercard.com
            payoneer.com
            wikipedia.org
            wikimedia.org
            w3schools.com
            coursera.org
            udemy.com
            nytimes.com
            bbc.com
            bbc.co.uk
            reuters.com
            bloomberg.com
            cnn.com
            forbes.com
            techcrunch.com
            netflix.com
            spotify.com
            twitch.tv
            disneyplus.com
            vimeo.com
            notion.so
            trello.com
            slack.com
            figma.com
            canva.com
            dropbox.com
            google.com.vn
            example.com""",
        alias="SAFE_WHITELIST_DOMAINS",
    )

    firestore_ttl: int = Field(
        default=604800,
        alias="FIRESTORE_TTL",
    )

    agent_api_key: str | None = Field(
        default=None,
        alias="AGENT_API_KEY",
    )

    # Scraping APIs
    # https://dashboard.scrape.do/overview
    scrape_do_token: str | None = Field(
        default=None,
        alias="SCRAPE_DO_TOKEN",
    )

    # https://dashboard.scraperapi.com/home
    scraper_api_key: str | None = Field(
        default=None,
        alias="SCRAPER_API_KEY",
    )

    # https://app.scrapingant.com/dashboard
    scraping_ant_api_key: str | None = Field(
        default=None,
        alias="SCRAPING_ANT_API_KEY",
    )

    max_concurrent_scans: int = Field(
        default=3,
        alias="MAX_CONCURRENT_SCANS",
    )

    backend_rate_limit_analyze_requests: int = Field(
        default=5,
        alias="BACKEND_RATE_LIMIT_ANALYZE_REQUESTS",
    )

    backend_rate_limit_history_requests: int = Field(
        default=30,
        alias="BACKEND_RATE_LIMIT_HISTORY_REQUESTS",
    )

    backend_rate_limit_window: int = Field(
        default=60,
        alias="BACKEND_RATE_LIMIT_WINDOW",
    )

    @property
    def whitelist_domains_set(self) -> set[str]:
        import re
        raw_domains = re.split(r'[,\n]', self.safe_whitelist_domains)
        return {d.strip().lower() for d in raw_domains if d.strip() and not d.strip().startswith("#")}

    def is_whitelisted(self, url: str) -> bool:
        """Checks if a URL's domain or root domain is in the safe whitelist set."""
        if not url:
            return False
        from urllib.parse import urlparse
        try:
            url_str = url if url.startswith(("http://", "https://")) else f"https://{url}"
            domain_lower = urlparse(url_str).netloc.lower().replace("www.", "")
            parts = domain_lower.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
            whitelist = self.whitelist_domains_set
            return root_domain in whitelist or domain_lower in whitelist
        except Exception:
            return False



settings = Settings()

if settings.google_application_credentials:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials
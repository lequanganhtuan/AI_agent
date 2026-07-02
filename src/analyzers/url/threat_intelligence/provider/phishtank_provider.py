from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.analyzers.url.threat_intelligence.provider.base_provider import (
    BaseThreatProvider,
    ProviderError,
    ThreatIntelInput,
)
from src.core.models import PhishTankAnalysis

logger = logging.getLogger(__name__)


class PhishTankProvider(BaseThreatProvider[PhishTankAnalysis]):
    PROVIDER_NAME: str = "PhishTank"

    # 1. __init__()
    def __init__(self) -> None:
        """Initialize Provider, configure parameters from configuration and store endpoint."""
        base_url = ThreatIntelConfig.PHISHTANK_BASE_URL
        endpoint_path = ThreatIntelConfig.PHISHTANK_LOOKUP_ENDPOINT
        timeout = ThreatIntelConfig.PHISHTANK_TIMEOUT_SECONDS

        if not base_url or not endpoint_path:
            logger.error("[%s] Initialization failed: Missing configuration.", self.PROVIDER_NAME)
            raise ValueError("PhishTank configuration is missing")

        super().__init__(timeout=timeout)
        self._endpoint = f"{base_url.rstrip('/')}{endpoint_path}"
        logger.info("[%s] Provider initialized successfully.", self.PROVIDER_NAME)

    # 2. lookup()
    async def lookup(self, threat_input: ThreatIntelInput) -> PhishTankAnalysis:
        """Public orchestrator for querying PhishTank database."""
        if not threat_input or not threat_input.normalized_url:
            logger.error("[%s] Validation failed: target normalized_url is missing.", self.PROVIDER_NAME)
            raise ValueError("Target input normalized_url cannot be null or empty")

        logger.info("[%s] Querying PhishTank database for URL.", self.PROVIDER_NAME)

        try:
            payload = self._build_request_payload(threat_input)
            response = await self._post_lookup(payload)
            return self.parse_response(response)
        except ProviderError:
            raise
        except Exception as exc:
            logger.exception("[%s] Lookup failed with unexpected exception.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Lookup failed: {exc}",
                status_code=500,
            ) from exc

    # 3. _build_request_payload()
    def _build_request_payload(self, threat_input: ThreatIntelInput) -> dict[str, Any]:
        """Constructs the request body according to the PhishTank API."""
        return {
            "url": threat_input.normalized_url,
            "format": "json"
        }

    # 4. _post_lookup()
    async def _post_lookup(self, payload: dict[str, Any]) -> httpx.Response:
        """Perform request I/O using self._safe_request."""
        return await self._safe_request(
            method="POST",
            url=self._endpoint,
            data=payload
        )

    # 5. parse_response()
    def parse_response(self, response: httpx.Response, **kwargs: Any) -> PhishTankAnalysis:
        """Convert HTTP Response into PhishTankAnalysis domain model."""
        self._validate_response_content_type(response)

        try:
            data = response.json()
            self._validate_payload(data)

            results = data["results"]
            return PhishTankAnalysis(
                in_database=self._extract_in_database(results),
                verified=self._extract_verified(results),
                verified_at=self._extract_submission_time(results),
                phish_detail_url=self._extract_details(results),
            )
        except ProviderError:
            raise
        except Exception as exc:
            logger.error("[%s] Failed to parse PhishTank response payload: %s", self.PROVIDER_NAME, exc)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Failed to parse PhishTank response payload: {exc}",
                status_code=response.status_code,
            ) from exc

    # 6. _validate_payload()
    def _validate_payload(self, data: dict[str, Any]) -> None:
        """Perform schema checks on response payload."""
        if not isinstance(data, dict):
            logger.error("[%s] Received response payload that is not a dictionary.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Invalid payload structure received",
                status_code=500,
            )
        if "results" not in data:
            logger.error("[%s] Schema violation: 'results' field is missing.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation failed: 'results' attribute is missing",
                status_code=502,
            )
        if not isinstance(data["results"], dict):
            logger.error("[%s] Schema violation: 'results' field is not a dictionary.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation failed: 'results' attribute must be a dict structure",
                status_code=502,
            )

    # 7. _extract_in_database()
    def _extract_in_database(self, results: dict[str, Any]) -> bool:
        """Check if URL exists in the database."""
        return bool(results.get("in_database", False))

    # 8. _extract_verified()
    def _extract_verified(self, results: dict[str, Any]) -> bool:
        """Extract verified status."""
        return bool(results.get("verified", False))

    # 9. _extract_valid()
    def _extract_valid(self, results: dict[str, Any]) -> bool:
        """Extract valid status."""
        return bool(results.get("valid", False))

    # 10. _extract_phish_id()
    def _extract_phish_id(self, results: dict[str, Any]) -> str | int | None:
        """Extract phish_id."""
        return results.get("phish_id")

    # 11. _extract_submission_time()
    def _extract_submission_time(self, results: dict[str, Any]) -> datetime | None:
        """Parse submission_time or verified_at to timezone-aware UTC datetime."""
        time_str = results.get("verified_at") or results.get("submission_time")
        if not time_str:
            return None

        time_str = str(time_str).strip()
        try:
            if time_str.endswith(" UTC"):
                dt_part = time_str[:-4].strip()
                return datetime.strptime(dt_part, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if time_str.endswith("Z"):
                time_str = time_str[:-1] + "+00:00"
            return datetime.fromisoformat(time_str)
        except (ValueError, TypeError):
            logger.warning("[%s] Failed to parse timestamp: %s", self.PROVIDER_NAME, time_str)
            return None

    # 12. _extract_details()
    def _extract_details(self, results: dict[str, Any]) -> str | None:
        """Extract phish_detail_page URL."""
        return results.get("phish_detail_page")

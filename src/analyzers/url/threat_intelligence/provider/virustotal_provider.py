from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    BaseThreatProvider,
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.core.models import VirusTotalAnalysis
from src.core.settings import settings

logger = logging.getLogger(__name__)


class VirusTotalProvider(BaseThreatProvider[VirusTotalAnalysis]):
    """
    VirusTotal API v3 Enterprise Provider.
    Designed with defensive programming principles, adhering strictly to
    the Single Responsibility Principle (SRP) through modular decomposition.
    """

    PROVIDER_NAME: str = "VirusTotal"

    # 1. LIFECYCLE & SETUP
    def __init__(self) -> None:
        """Initialize and configure the client. Must not contain business logic."""
        super().__init__(timeout=ThreatIntelConfig.VIRUSTOTAL_TIMEOUT)

        api_key = settings.virustotal_api_key
        if not api_key:
            raise ValueError("VIRUSTOTAL_API_KEY is not configured.")

        self._api_key = api_key
        self.client.headers.update({
            "x-apikey": self._api_key,
            "Accept": "application/json"
        })

        self._base_url = ThreatIntelConfig.VIRUSTOTAL_BASE_URL.rstrip("/")
        self._poll_interval = ThreatIntelConfig.VIRUSTOTAL_POLL_INTERVAL
        self._max_poll_attempts = ThreatIntelConfig.VIRUSTOTAL_MAX_POLL_ATTEMPTS

    # 2. PUBLIC ORCHESTRATOR
    async def lookup(self, target: ThreatIntelInput) -> VirusTotalAnalysis:
        """
        Public API Orchestrator.
        Operates linearly: Cache-First -> Submit -> Poll -> Parse.
        """
        if not target or not target.normalized_url:
            raise ValueError("Target input or normalized URL cannot be empty.")

        logger.info(ThreatIntelConfig.LOG_REQUEST_START, self.PROVIDER_NAME)
        url_id = self._build_url_id(target.normalized_url)

        try:
            # Step 1: Look up historical report (Cache-First)
            existing_response = await self._lookup_existing_report(url_id)
            if existing_response is not None:
                return self.parse_response(existing_response)

            # Step 2: Fallback - Submit new URL to Sandbox
            logger.info("[%s] Record does not exist. Initiating URL submit command.", self.PROVIDER_NAME)
            analysis_id = await self._submit_url(target.normalized_url)

            # Step 3: Poll the analysis state machine
            analysis_response = await self._poll_analysis(analysis_id)

            # Step 4: Parse the final response payload
            result_dto = self.parse_response(analysis_response)
            logger.info(ThreatIntelConfig.LOG_REQUEST_SUCCESS, self.PROVIDER_NAME)
            return result_dto

        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Orchestration fatal failure: {str(exc)}"
            ) from exc

    # 3. CORE PRIVATE WORKFLOWS
    def _build_url_id(self, url: str) -> str:
        """Encode URL to unpadded URL-safe Base64 format as per VT v3 specification."""
        if not url:
            raise ValueError("URL string cannot be empty for ID generation.")
        encoded_bytes = base64.urlsafe_b64encode(url.encode("utf-8"))
        return encoded_bytes.decode("utf-8").rstrip("=")

    async def _lookup_existing_report(self, url_id: str) -> httpx.Response | None:
        """Look up cached report. Detect 404/NotFoundError based on both status code and response body."""
        endpoint = f"{self._base_url}/urls/{url_id}"
        response = await self._safe_request("GET", endpoint, raise_for_status=False)

        if response.status_code == 200:
            return response

        # Double defense: Check for HTTP 404 or NotFoundError business error code in JSON
        if self._is_not_found(response):
            return None

        raise ProviderError(
            provider=self.PROVIDER_NAME,
            message=f"Failed historical report retrieval. Status: {response.status_code}",
            status_code=response.status_code
        )

    async def _submit_url(self, url: str) -> str:
        """Send POST request to queue the URL for Sandbox analysis."""
        endpoint = f"{self._base_url}/urls"
        payload = {"url": url}
        response = await self._safe_request("POST", endpoint, data=payload, raise_for_status=True)
        return self._extract_analysis_id(response)

    async def _poll_analysis(self, analysis_id: str) -> httpx.Response:
        """Polling state machine loop. Fail-Fast mechanism to prevent hanging/stuck processes."""
        endpoint = f"{self._base_url}/analyses/{analysis_id}"

        for attempt in range(1, self._max_poll_attempts + 1):
            await self._sleep_before_next_poll()

            response = await self._safe_request("GET", endpoint, raise_for_status=True)
            status = self._extract_status(response)

            match status:
                case "completed":
                    logger.info("[%s] Sandbox analysis completed successfully.", self.PROVIDER_NAME)
                    return response
                case "queued" | "in-progress":
                    continue
                case _:
                    # Fail-Fast mechanism: intercept immediately if the API returns failed, cancelled, etc.
                    raise ProviderError(
                        provider=self.PROVIDER_NAME,
                        message=f"Analysis terminated with unexpected status: '{status}'",
                        status_code=response.status_code
                    )

        logger.error(ThreatIntelConfig.LOG_TIMEOUT, self.PROVIDER_NAME)
        raise ProviderError(
            provider=self.PROVIDER_NAME,
            message=f"Polling lifecycle expired. Task incomplete after {self._max_poll_attempts} attempts.",
            status_code=408
        )

    # 4. GRANULAR UTILITIES
    def _validate_response_content_type(self, response: httpx.Response) -> None:
        """Early interception of non-JSON responses (e.g., Cloudflare WAF HTML, proxy errors)."""
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Expected JSON response but received Content-Type '{content_type}'. Body truncated: {response.text[:200]}",
                status_code=response.status_code
            )

    def _validate_business_error(self, payload: dict[str, Any], response: httpx.Response) -> None:
        """Verify and process structured business error blocks nested inside JSON."""
        if "error" in payload:
            err_body = payload["error"]
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"API Business Error [{err_body.get('code')}]: {err_body.get('message')}",
                status_code=response.status_code
            )

    def _is_not_found(self, response: httpx.Response) -> bool:
        """Check boundary conditions for Not Found (HTTP 404 or NotFoundError in JSON)."""
        if response.status_code == 404:
            return True

        # Check deeper in case a WAF or API returns 200/400 with a NotFound error
        try:
            self._validate_response_content_type(response)
            payload = response.json()
            if payload.get("error", {}).get("code") == "NotFoundError":
                return True
        except Exception:
            pass

        return False

    def _extract_analysis_id(self, response: httpx.Response) -> str:
        """Extract analysis ID from the POST endpoint response."""
        self._validate_response_content_type(response)
        try:
            payload = response.json()
            self._validate_business_error(payload, response)
            return str(payload["data"]["id"])
        except (KeyError, TypeError) as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Invalid payload shape on submission endpoint: {str(exc)}",
                status_code=response.status_code
            ) from exc

    def _extract_status(self, response: httpx.Response) -> str:
        """Extract Sandbox analysis status from the polling response."""
        self._validate_response_content_type(response)
        try:
            payload = response.json()
            self._validate_business_error(payload, response)
            return str(payload["data"]["attributes"]["status"])
        except (KeyError, TypeError) as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Invalid payload shape on analysis metadata fetching: {str(exc)}",
                status_code=response.status_code
            ) from exc

    async def _sleep_before_next_poll(self) -> None:
        """Isolated sleep wrapper to facilitate future upgrades to Exponential Backoff."""
        await asyncio.sleep(self._poll_interval)

    # 5. PURE PARSER CORNER
    def parse_response(self, response: httpx.Response) -> VirusTotalAnalysis:
        """
        Pure parser function to convert raw response to Pydantic Model.
        Decomposed into helper methods for readability and maintainability.
        """
        self._validate_response_content_type(response)

        try:
            payload = response.json()
            self._validate_business_error(payload, response)

            attributes = self._extract_attributes(payload)
            stats, results = self._extract_statistics(attributes)
            categories = self._extract_categories(results)
            scan_date = self._extract_scan_date(attributes)

            # Compute total engines as the sum of all status values
            total_engines = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))

            return VirusTotalAnalysis(
                total_engines=total_engines,
                malicious=malicious_count,
                suspicious=suspicious_count,
                harmless=int(stats.get("harmless", 0)),
                undetected=int(stats.get("undetected", 0)),
                categories=categories,
                scan_date=scan_date,
                found=bool(malicious_count > 0 or suspicious_count > 0)
            )

        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Failed to parse internal schema fields: {str(exc)}",
                status_code=response.status_code
            ) from exc

    def _extract_attributes(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Safely extract core attributes block from the raw JSON payload."""
        attributes = payload.get("data", {}).get("attributes")
        if not isinstance(attributes, dict):
            raise KeyError("Missing core 'data.attributes' map in VirusTotal payload.")
        return attributes

    def _extract_statistics(self, attributes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Polymorphic extractor to get statistics and results from both types of endpoints."""
        if "last_analysis_stats" in attributes:
            # Attribute shape for GET /urls/{id}
            return attributes["last_analysis_stats"], attributes.get("last_analysis_results", {})
        elif "stats" in attributes:
            # Attribute shape for GET /analyses/{id}
            return attributes["stats"], attributes.get("results", {})

        raise KeyError("Polymorphic parser failed: Neither 'last_analysis_stats' nor 'stats' found.")

    def _extract_categories(self, results: dict[str, Any]) -> list[str]:
        """Extract unique malware signatures (verdicts) from AV engines."""
        unique_verdicts: set[str] = set()
        if not isinstance(results, dict):
            return []

        for engine_meta in results.values():
            if not isinstance(engine_meta, dict):
                continue
            category = engine_meta.get("category")
            # Only take the 'result' field value (specific malware signature like Phishing, Trojan, etc.)
            verdict = engine_meta.get("result")
            if category in ("malicious", "suspicious") and verdict:
                unique_verdicts.add(str(verdict))

        return list(unique_verdicts)

    def _extract_scan_date(self, attributes: dict[str, Any]) -> datetime | None:
        """Read and parse Epoch timestamp into a timezone-aware UTC datetime."""
        scan_date_epoch = attributes.get("last_analysis_date") or attributes.get("date")
        if not scan_date_epoch:
            return None

        try:
            return datetime.fromtimestamp(float(scan_date_epoch), tz=timezone.utc)
        except (ValueError, TypeError):
            logger.warning("[%s] Invalid Epoch timestamp: %s. Cannot convert.", self.PROVIDER_NAME, scan_date_epoch)
            return None
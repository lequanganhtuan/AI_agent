from __future__ import annotations

from src.core.settings import settings

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
from src.core.models import URLHausAnalysis

logger = logging.getLogger(__name__)


class URLHausProvider(BaseThreatProvider[URLHausAnalysis]):
    """URLHaus Threat Intelligence Lookup Provider.
    
    A high-resilience implementation synchronized with base structural contracts,
    equipped with defensive query status extraction and schema validation layers.
    """

    PROVIDER_NAME: str = "URLHaus"

    # 1. SETUP
    def __init__(self) -> None:
        """Initialize Provider, configure parameters from centralized settings, and resolve endpoint."""
        
        api_key       = settings.urlhaus_api_key
        base_url      = ThreatIntelConfig.URLHAUS_BASE_URL
        endpoint_path = ThreatIntelConfig.URLHAUS_LOOKUP_ENDPOINT
        
        if not api_key or not base_url or not endpoint_path:
            logger.error("[%s] Inititation failed: URLHAUS_API_KEY or Base URL or Endpoint Path is not configured.", self.PROVIDER_NAME)
            raise ValueError("URLHAUS_API_KEY or Base URL or Endpoint Path is not configured in settings.")

        super().__init__(ThreatIntelConfig.URLHAUS_TIMEOUT_SECONDS)
        
        self._api_key  = api_key
        self._endpoint = f"{base_url.rstrip('/')}{endpoint_path}"
        self._base_url = self._endpoint
        
        logger.info("[%s] Provider initialized successfully.", self.PROVIDER_NAME)

    # 2. lookup() - Pure Orchestrator Layer
    async def lookup(self, threat_input: ThreatIntelInput, **kwargs: Any) -> URLHausAnalysis:
        """Public orchestrator for querying the URLHaus threat database."""
        url = threat_input.normalized_url.strip()
        if not url:
            logger.error("[%s] Validation failed: target normalized_url is missing.", self.PROVIDER_NAME)
            raise ValueError("Target input normalized_url cannot be null or empty")

        logger.info(ThreatIntelConfig.LOG_REQUEST_START, self.PROVIDER_NAME, url)

        try:
            payload = self._build_request_payload(threat_input)
            analysis_response = await self._post_lookup(payload)
            result_dto = self.parse_response(analysis_response, **kwargs)
            logger.info(ThreatIntelConfig.LOG_REQUEST_SUCCESS, self.PROVIDER_NAME)
            return result_dto
        except ProviderError:
            raise
        except Exception as exc:
            logger.exception("[%s] Lookup failed with unhandled engine exception.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Lookup failed: {exc}",
                status_code=500,
                raw_error_type="UncaughtPipelineExplosion"
            ) from exc

    def _build_request_payload(self, threat_input: ThreatIntelInput) -> dict[str, Any]:
        """Build request payload for URLHaus api."""
        return {"url": threat_input.normalized_url}

    async def _post_lookup(self, payload: dict[str, Any]) -> httpx.Response:
        """Perform network I/O block utilizing base class safe transport mechanics."""
        headers = {}
        if self._api_key:
            headers["Auth-Key"] = self._api_key
        return await self._safe_request(
            method="POST",
            url=self._base_url,
            data=payload,
            headers=headers
        )

    # 4. parse_response() - Highly Resilient Parser (Pure Function)
    def parse_response(self, response: httpx.Response, **kwargs: Any) -> URLHausAnalysis:
        """Convert HTTP Response packet into structured URLHausAnalysis domain models."""
        self._validate_response_content_type(response)
        
        # SỬA LỖI 4: Guard check rỗng phòng thủ mất kết nối hoặc rớt gói tin giữa chừng
        if not response.text or not response.text.strip():
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Upstream provider returned an empty or unparsable response body stream.",
                status_code=502,
                raw_error_type="EmptyUpstreamResponse"
            )

        try:
            data = response.json()
        except Exception as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Failed to parse URLHaus response payload: {exc}",
                status_code=422,
                raw_error_type="NonParsableJSON"
            ) from exc

        try:
            self._validate_payload(data, response.status_code)

            return URLHausAnalysis(
                query_status=self._extract_query_status(data),
                url_status=self._extract_url_status(data),
                threat=self._extract_threat(data),
                tags=self._extract_tags(data),
                reporter=self._extract_reporter(data),
                first_seen=self._extract_first_seen(data),
                payloads=self._extract_payloads(data),
            )
        except ProviderError:
            raise
        except Exception as exc:
            logger.error("[%s] Serialization mapping crash on data stream payload: %s", self.PROVIDER_NAME, exc)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Failed to map URLHaus JSON token to data model: {exc}",
                status_code=response.status_code,
                raw_error_type="SerializationFailure"
            ) from exc

    # 5. _validate_payload() - Rich Semantic Business Classification
    def _validate_payload(self, data: dict[str, Any], raw_http_status: int = 200) -> None:
        """Perform deep business semantic analysis on response structural schemas."""
        # Phòng thủ lỗi 429 Rate Limit ở tầng HTTP Status
        if raw_http_status == 429:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="URLHaus API lookup rate limit threshold breached.",
                status_code=429,
                raw_error_type="RateLimitExceeded"
            )

        if not isinstance(data, dict):
            logger.error("[%s] Received response payload that is not a dictionary.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Invalid JSON payload structure received",
                status_code=500,
                raw_error_type="UnexpectedSchemaRoot"
            )
            
        # SỬA LỖI 1 & 2: Phân loại giàu ngữ cảnh dựa trên mã kinh doanh query_status
        if "query_status" not in data:
            logger.error("[%s] Schema violation: 'query_status' field is missing.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation failed: Missing required field 'query_status' from endpoint data.",
                status_code=502,
                raw_error_type="SchemaViolation"
            )

        query_status = str(data["query_status"]).strip().lower()
        
        # Nhận diện trạng thái lỗi gửi dữ liệu không hợp lệ từ phía client (Ví dụ: truyền rỗng/sai url format)
        if query_status == "invalid":
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="URLHaus rejected the lookup request because the provided target criteria is invalid.",
                status_code=422,
                raw_error_type="InvalidTargetInput"
            )

    # 6. Tầng Hàm Con Trích Xuất Dữ Liệu An Toàn (Defensive Extractors)
    def _extract_query_status(self, data: dict[str, Any]) -> str:
        status = data.get("query_status")
        return str(status).strip().lower() if status is not None else "unknown"

    def _extract_url_status(self, data: dict[str, Any]) -> str | None:
        status = data.get("url_status")
        return str(status).strip().lower() if status is not None else None

    def _extract_threat(self, data: dict[str, Any]) -> str | None:
        return data.get("threat")

    def _extract_tags(self, data: dict[str, Any]) -> list[str]:
        tags = data.get("tags")
        if isinstance(tags, list):
            return [str(tag).strip() for tag in tags if tag is not None]
        return []

    def _extract_reporter(self, data: dict[str, Any]) -> str | None:
        return data.get("reporter")

    def _extract_first_seen(self, data: dict[str, Any]) -> datetime | None:
        """Parse 'firstseen' field and return a timezone-aware UTC datetime."""
        first_seen_str = data.get("firstseen")
        if not first_seen_str:
            return None

        # Định dạng chuẩn: "2026-05-01 11:20:30 UTC" hoặc "2026-05-01 11:20:30"
        first_seen_str = str(first_seen_str).strip()
        try:
            if first_seen_str.endswith(" UTC"):
                dt_part = first_seen_str[:-4].strip()
                return datetime.strptime(dt_part, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            logger.warning("[%s] Failed to parse firstseen timestamp: %s", self.PROVIDER_NAME, first_seen_str)
            return None

    def _extract_payloads(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        payloads = data.get("payloads")
        if isinstance(payloads, list):
            return [p for p in payloads if isinstance(p, dict)]
        return []
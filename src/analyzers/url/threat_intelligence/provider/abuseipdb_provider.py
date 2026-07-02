from __future__ import annotations

import logging
from typing import Any

import httpx

from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.analyzers.url.threat_intelligence.provider.base_provider import (
    BaseThreatProvider,
    ProviderError,
    ThreatIntelInput,
)
from src.core.models import AbuseIPDBAnalysis
from src.core.settings import settings

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(BaseThreatProvider[AbuseIPDBAnalysis]):
    """AbuseIPDB Reputation Lookup Provider.
    
    A high-precision, defensive implementation for fetching remote network
    reputation scores, fortified with explicit mock fallback lifecycle guards
    and zero-leak credentials hardening.
    """

    PROVIDER_NAME: str = "AbuseIPDB"

    # 1. __init__()
    def __init__(self) -> None:
        """Initialize Provider with API credentials, configuration constants, and base URL."""
        api_key = settings.abuseipdb_api_key
        base_url = ThreatIntelConfig.ABUSEIPDB_BASE_URL

        if not base_url:
            logger.error("[%s] Initialization failed: Missing base URL destination configuration.", self.PROVIDER_NAME)
            raise ValueError("AbuseIPDB base URL configuration is missing")
        
        if not api_key:
            logger.warning(
                "[%s] Security Configuration Warning: API key is not configured in environment settings. "
                "Provider entering isolated safety fallback mode.", 
                self.PROVIDER_NAME
            )
            self._api_key = None
            self._mock_mode = True
        else:
            self._api_key = api_key
            self._mock_mode = False

        super().__init__(ThreatIntelConfig.ABUSEIPDB_TIMEOUT_SECONDS)
        self._base_url = base_url.rstrip("/")

        logger.info("[%s] Provider initialized successfully. Mock mode status: %s", self.PROVIDER_NAME, self._mock_mode)

    # 2. lookup() - Core Entry Point
    async def lookup(self, threat_input: ThreatIntelInput, **kwargs: Any) -> AbuseIPDBAnalysis:
        """Public orchestrator for performing IP Reputation checks."""
        if not threat_input:
            raise ValueError("Threat input target object cannot be null or empty")

        ip = threat_input.ip_address.strip() if threat_input.ip_address else ""
        if not ip:
            logger.debug("[%s] No IP address context populated. Returning default clean analysis.", self.PROVIDER_NAME)
            return self._generate_clean_default_analysis()

        # CHẶN ĐỨNG FAKE RESPONSE: Nếu ở chế độ Mock Mode, trả về cấu trúc mô phỏng an toàn thay vì Object rỗng rách dữ liệu
        if self._mock_mode:
            logger.info("[%s] Mock mode active. Shunting network I/O block, returning semantic fallback model.", self.PROVIDER_NAME)
            return self._generate_clean_default_analysis()

        logger.info("[%s] Querying live IP reputation score for target node: %s", self.PROVIDER_NAME, ip)

        try:
            analysis_response = await self._fetch_abuseipdb_metadata(ip)
            result_dto = self.parse_response(analysis_response, **kwargs)

            logger.info("[%s] IP Reputation check completed for node: %s", self.PROVIDER_NAME, ip)
            return result_dto

        except ProviderError:
            raise  # Đẩy thẳng các lỗi đã phân loại lên tầng Orchestrator
        except Exception as exc:
            # Phòng thủ chủ động bảo mật: Ẩn api_key khỏi thông điệp log nếu exc chứa thông tin endpoint raw
            error_msg = str(exc)
            if self._api_key and self._api_key in error_msg:
                error_msg = error_msg.replace(self._api_key, "REDACTED_API_KEY")

            logger.error("[%s] Unexpected core pipeline failure during upstream query: %s", self.PROVIDER_NAME, error_msg)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"IPQS query execution crashed unexpectedly: {error_msg}",
                status_code=500,
                raw_error_type="UncaughtInternalExplosion"
            ) from exc

    # 3. _fetch_abuseipdb_metadata() - Clean Encapsulated Network Transport
    async def _fetch_abuseipdb_metadata(self, ip: str) -> httpx.Response:
        """Perform request I/O strictly bounded by base class transport mechanics."""
        endpoint = f"{self._base_url}/check"
        headers = {
            "Key": self._api_key or "",
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        
        try:
            # Gọi qua _safe_request để hưởng đầy đủ cơ chế Retry, Timeout và Circuit Breaker
            return await self._safe_request(
                method="GET",
                url=endpoint,
                headers=headers,
                params=params
            )
        except Exception as exc:
            # Bắt vết và bóc tách API Key ngay lập tức tại tầng Network nếu có Exception ném ra ngoài
            msg = str(exc)
            if self._api_key and self._api_key in msg:
                msg = msg.replace(self._api_key, "REDACTED_API_KEY")
            raise RuntimeError(f"Transport layer failure wrapped: {msg}") from exc

    # 4. parse_response() - Highly Resilient Parser Function
    def parse_response(self, response: httpx.Response, **kwargs: Any) -> AbuseIPDBAnalysis:
        """Convert standard HTTP Response structural data into domain models safely."""
        if hasattr(self, "_validate_response_content_type"):
            self._validate_response_content_type(response)

        try:
            payload = response.json()
            self._validate_payload(payload, response.status_code)

            data = payload.get("data", {})

            # Khai thác dữ liệu an toàn phòng thủ lỗi kiểu dữ liệu ngầm từ API bên thứ 3
            return AbuseIPDBAnalysis(
                ip_address=data.get("ipAddress", ""),
                abuse_score=int(data.get("abuseConfidenceScore", 0)),
                total_reports=int(data.get("totalReports", 0)),
                usage_type=data.get("usageType"),
                country_code=data.get("countryCode"),
                domain=data.get("domain"),
                confidence=100
            )
        except ProviderError:
            raise
        except Exception as exc:
            logger.error("[%s] Fatal crash parsing API response stream payload: %s", self.PROVIDER_NAME, exc)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"AbuseIPDB response JSON token transformation failed: {exc}",
                status_code=response.status_code,
                raw_error_type="SerializationFailure"
            ) from exc

    # 5. _validate_payload() - Rich Error Classification Layer
    def _validate_payload(self, data: dict[str, Any], raw_http_status: int) -> None:
        """Perform deep business schema checking with semantic error classification."""
        if not isinstance(data, dict):
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="AbuseIPDB payload structure breach: Expected JSON Object map context.",
                status_code=500,
                raw_error_type="UnexpectedSchemaRoot"
            )

        # Handle AbuseIPDB error schema (errors array compliance with JSON API)
        if "errors" in data and isinstance(data["errors"], list) and len(data["errors"]) > 0:
            first_error = data["errors"][0]
            msg = first_error.get("detail", "API transaction flagged as unsuccessful")
            status_code = first_error.get("status", raw_http_status)
            
            error_type = "API_Business_Refusal"
            if status_code == 401:
                error_type = "AuthenticationFailure"
            elif status_code == 429:
                error_type = "RateLimitExceeded"
            elif status_code == 422:
                error_type = "InvalidTargetInput"

            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"AbuseIPDB Operational Rejection: {msg}",
                status_code=status_code,
                raw_error_type=error_type
            )

    def _generate_clean_default_analysis(self) -> AbuseIPDBAnalysis:
        return AbuseIPDBAnalysis(
            ip_address="",
            abuse_score=0,
            total_reports=0,
            usage_type=None,
            country_code=None,
            domain=None,
            confidence=100
        )
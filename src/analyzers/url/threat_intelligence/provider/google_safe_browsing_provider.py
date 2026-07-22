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
from src.core.models import GoogleSafeBrowsingAnalysis
from src.core.settings import settings

# Thiết lập Logger đồng bộ hệ thống
logger = logging.getLogger(__name__)


class GoogleSafeBrowsingProvider(BaseThreatProvider[GoogleSafeBrowsingAnalysis]):
    PROVIDER_NAME: str = "GoogleSafeBrowsing"
    # 1. __init__()
    def __init__(self) -> None:
        """Khởi tạo Provider, cấu hình thông số qua lớp cha và nạp API Key."""
        api_key = settings.google_safe_browsing_api_key
        base_url = ThreatIntelConfig.GOOGLE_SAFE_BROWSING_BASE_URL
        endpoint_path = ThreatIntelConfig.GOOGLE_SAFE_BROWSING_LOOKUP_ENDPOINT

        if not api_key:
            logger.error("[%s] Initialization failed: API key not configured.", self.PROVIDER_NAME)
            raise ValueError("GOOGLE_SAFE_BROWSING_API_KEY is not configured in settings.")

        if not base_url or not endpoint_path:
            logger.error("[%s] Initialization failed: Base URL or endpoint is not configured.", self.PROVIDER_NAME)
            raise ValueError("GOOGLE_SAFE_BROWSING_API_KEY or Base URL is not configured in settings.")
            
        super().__init__(ThreatIntelConfig.GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS)
        
        self._api_key = api_key
        self._base_url = f"{base_url.rstrip('/')}{endpoint_path}"
        self._client_id = "ai-threat-intelligence-pipeline"
        self._client_version = "1.0.0"
        
        logger.info("[%s] Provider initialized successfully in enterprise state.", self.PROVIDER_NAME)

    # 2. lookup() - Public Orchestrator
    async def lookup(self, threat_input: ThreatIntelInput, **kwargs: Any) -> GoogleSafeBrowsingAnalysis:
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
            logger.exception("[%s] Lookup failed.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Lookup failed: {exc}",
                status_code=500,
            ) from exc

    # 3. _build_request_payload()
    def _build_request_payload(self, threat_input: ThreatIntelInput) -> dict[str, Any]:
        """Tạo cấu trúc dict payload đáp ứng chính xác đặc tả Google Safe Browsing v4."""
        return {
            "client": {
                "clientId": self._client_id,
                "clientVersion": self._client_version
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE", 
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": threat_input.normalized_url}
                ]
            }
        }

    # 4. _post_lookup()
    async def _post_lookup(self, payload: dict[str, Any]) -> httpx.Response:
        """Thực hiện request I/O thông qua cơ chế an toàn của BaseProvider."""
        return await self._safe_request(
            method="POST",
            url=self._base_url,
            params={"key": self._api_key},
            json=payload
        )

    # 5. parse_response()
    def parse_response(self, response: httpx.Response, **kwargs: Any) -> GoogleSafeBrowsingAnalysis:
        """Chuyển đổi HTTP Response sang Model nghiệp vụ và phòng vệ ngoại lệ."""
        self._validate_response_content_type(response)

        if not response.text or not response.text.strip():
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Upstream provider returned an empty or unparsable response body stream.",
                status_code=502,
                raw_error_type="EmptyUpstreamResponse"
            )
        
        try:
            data = response.json()
            self._validate_payload(data)

            matches = self._extract_matches(data)
            is_found = len(matches) > 0
            
            if is_found:
                logger.warning(
                    "[%s] Threat detected by Google Safe Browsing. Match count: %d", 
                    self.PROVIDER_NAME, len(matches)
                )
            else:
                logger.info("[%s] URL marked as clean by Google Safe Browsing.", self.PROVIDER_NAME)

            return GoogleSafeBrowsingAnalysis(
                threat_found=is_found,
                threat_type=self._extract_threat_type(matches),
                platform_type=self._extract_platform(matches),
                cache_duration=self._extract_cache_duration(matches)
            )
            
        except ProviderError:
            # Nếu _validate_payload ném ProviderError, cho qua để không bị map nhầm thành lỗi 500 JSON
            raise
            
        except Exception as exc:
            logger.error("[%s] Failed to parse Google Safe Browsing payload: %s", self.PROVIDER_NAME, exc)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Failed to parse Google Safe Browsing payload: {exc}",
                status_code=response.status_code,
                raw_error_type="ParsingError"
            ) from exc

    # Helper Trích Xuất Đối Tượng Đầu Tiên (Tối Ưu Đồng Bộ Tái Sử Dụng)
    def _first_match(self, matches: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Lấy phần tử đe dọa đầu tiên và phòng vệ kiểu dữ liệu.
        
        Giúp rút gọn mã nguồn cho nhóm hàm bóc tách dữ liệu.
        """
        if not matches:
            return None
            
        first = matches[0]
        if not isinstance(first, dict):
            logger.error("[%s] Parser warning: First match element is not a dict.", self.PROVIDER_NAME)
            return None
            
        return first

    # 6. _extract_matches()
    def _extract_matches(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Bóc tách danh sách các matches được trả về."""
        if "matches" not in data or data["matches"] is None:
            return []
        matches = data["matches"]
        if not isinstance(matches, list):
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Google Safe Browsing matches must be a list structure",
                status_code=502,
                raw_error_type="InvalidResponseStructure"
            )
        return matches

    # 7. _extract_threat_type()
    def _extract_threat_type(self, matches: list[dict[str, Any]]) -> str | None:
        """Lấy kiểu loại độc hại (ví dụ: MALWARE)."""
        match = self._first_match(matches)
        return match.get("threatType") if match else None

    # 8. _extract_platform()
    def _extract_platform(self, matches: list[dict[str, Any]]) -> str | None:
        """Lấy nền tảng độc hại (ví dụ: ANY_PLATFORM)."""
        match = self._first_match(matches)
        return match.get("platformType") if match else None

    # 9. _extract_cache_duration()
    def _extract_cache_duration(self, matches: list[dict[str, Any]]) -> str | None:
        """Lấy thời hạn cache khuyến nghị (ví dụ: '300s')."""
        match = self._first_match(matches)
        return match.get("cacheDuration") if match else None

    # 10. _validate_payload()
    def _validate_payload(self, data: dict[str, Any]) -> None:
        """Kiểm tra schema payload và bóc tách lỗi Business ẩn sâu."""
        if not isinstance(data, dict):
            logger.error("[%s] Received response payload that is not a dictionary.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME, 
                message="Invalid JSON payload structure received", 
                status_code=500
            )
            
        if "error" in data:
            error_block = data["error"]
            if not isinstance(error_block, dict):
                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message="Invalid Google Business Error Block format",
                    status_code=500
                )
                
            code = error_block.get("code", 400)
            message = error_block.get("message", "Unknown business error occurred")
            status = error_block.get("status", "BAD_REQUEST")
            
            logger.error(
                "[%s] Google API business error. Status: %s, Message: %s", 
                self.PROVIDER_NAME, status, message
            )
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Google Business Error [{status}]: {message}",
                status_code=code
            )

        if "matches" in data and not isinstance(data.get("matches"), list):
            logger.error("[%s] Schema violation: 'matches' field is not a list.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation failed: 'matches' attribute must be a list structure",
                status_code=502
            )


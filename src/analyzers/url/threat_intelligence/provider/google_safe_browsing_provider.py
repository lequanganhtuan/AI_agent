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
        if not settings.google_safe_browsing_api_key:
            logger.error("[%s] Initialization failed: Missing API Key.", self.PROVIDER_NAME)
            raise ValueError("GOOGLE_SAFE_BROWSING_API_KEY is not configured in settings")
            
        super().__init__(timeout=ThreatIntelConfig.GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS)
        
        self._api_key = settings.google_safe_browsing_api_key
        
        self._base_url = (
            f"{ThreatIntelConfig.GOOGLE_SAFE_BROWSING_BASE_URL}"
            f"{ThreatIntelConfig.GOOGLE_SAFE_BROWSING_LOOKUP_ENDPOINT}"
        )
        
        self._client_id = "ai-threat-intelligence-pipeline"
        self._client_version = "1.0.0"
        
        logger.info("[%s] Provider initialized successfully in enterprise state.", self.PROVIDER_NAME)

    # 2. lookup() - Public Orchestrator
    async def lookup(self, threat_input: ThreatIntelInput) -> GoogleSafeBrowsingAnalysis:
        if not threat_input.normalized_url:
            logger.error("[%s] Validation failed: target normalized_url is missing.", self.PROVIDER_NAME)
            raise ValueError("Target input normalized_url cannot be null or empty")

        logger.info(
            "[%s] Sending request to Google Safe Browsing. Domain: %s", 
            self.PROVIDER_NAME, 
            threat_input.domain
        )

        try:    
            payload = self._build_request_payload(threat_input)
            response = await self._post_lookup(payload)
            
            logger.info("[%s] Lookup completed.", self.PROVIDER_NAME)
            return self.parse_response(response)
            
        except ProviderError:
            # Cho phép lỗi bay thẳng lên trên, giữ nguyên trạng thái gốc (429 giữ nguyên 429)
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
    def parse_response(self, response: httpx.Response) -> GoogleSafeBrowsingAnalysis:
        """Chuyển đổi HTTP Response sang Model nghiệp vụ và phòng vệ ngoại lệ."""
        self._validate_response_content_type(response)
        
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
        matches = data.get("matches")
        if matches is None:
            return []

        if not isinstance(matches, list):
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation failed: 'matches' attribute must be a list structure",
                status_code=502
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

        if "matches" in data:
            matches = data.get("matches")
            if not isinstance(matches, list):
                logger.error("[%s] Schema violation: 'matches' field is not a list.", self.PROVIDER_NAME)
                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message="Schema validation failed: 'matches' attribute must be a list structure",
                    status_code=502
                )

    def _validate_response_content_type(self, response: httpx.Response) -> None:
        """Kiểm tra xem content-type của response có chứa application/json không (chặn WAF/proxy HTML)."""
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Expected JSON response but received Content-Type '{content_type}'",
                status_code=response.status_code
            )
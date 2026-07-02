from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class ThreatIntelInput(BaseModel):
    """Immutable Data Transfer Object (DTO) shared by all external Threat Intelligence providers."""

    model_config = ConfigDict(frozen=True)

    normalized_url: str = Field(..., description="Normalized URL generated during preprocessing.")
    domain: str = Field(..., description="Extracted root/full domain.")
    ip_address: str | None = Field(default=None, description="Resolved IPv4/IPv6 address if available.")
    cache_key: str | None = Field(default=None, description="Redis cache key shared across providers.")


class ProviderError(Exception):
    """Unified exception raised by every Threat Intelligence provider with semantic error typing."""

    def __init__(
        self,
        provider: str,
        message: str,
        status_code: int | None = None,
        raw_error_type: str | None = None, 
    ) -> None:
        self.provider = provider
        self.message = message
        self.status_code = status_code
        self.raw_error_type = raw_error_type or "UnknownError"
        super().__init__(self.__str__())

    def __str__(self) -> str:
        ctx = f" [{self.raw_error_type}]" if self.raw_error_type else ""
        if self.status_code is None:
            return f"[{self.provider}]{ctx} {self.message}"
        return f"[{self.provider}]{ctx} HTTP {self.status_code} - {self.message}"


class BaseThreatProvider(ABC, Generic[T]):
    """Abstract base class providing centralized, resilient HTTP capabilities for Threat Intelligence."""

    PROVIDER_NAME: str = "Base"

    # Status codes that are valid business responses, not transport errors.
    _NON_ERROR_STATUSES: frozenset[int] = frozenset({200, 404, 429})

    def __init__(self, timeout: float) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Read-only access to the shared Async HTTP client.
        
        Sử dụng cơ chế Lazy Initialization để đảm bảo Client Connection Pool 
        luôn luôn gắn chặt (bound) vào đúng Running Event Loop hiện tại của Request Task.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=100,
                ),
                headers={
                    "User-Agent": "AI-URL-Fraud-Detection-System/2.0 (Enterprise-Gateway)"
                },
            )
        return self._client

    @abstractmethod
    async def lookup(self, threat_input: ThreatIntelInput) -> T:
        """Execute a provider-specific lookup request."""
        raise NotImplementedError

    @abstractmethod
    def parse_response(self, response: httpx.Response, **kwargs: Any) -> T:
        """Convert raw HTTP response into a provider-specific Pydantic model.
        
        Sử dụng **kwargs để cho phép các lớp con nhận thêm metadata (như scan_id) 
        từ Orchestrator mà không phá vỡ tính Immutability của DTO.
        """
        raise NotImplementedError

    def _validate_response_content_type(self, response: httpx.Response) -> None:
        """Validate that a 200 response carries an application/json Content-Type."""
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Transport Validation Error: Expected JSON context but received Content-Type '{content_type}'",
                status_code=response.status_code,
                raw_error_type="ContentTypeMismatch",
            )

    async def _safe_request(
        self,
        method: str,
        url: str,
        *,
        raise_for_status: bool = True,
        intercept_429: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an HTTP request with unified error handling, logging, and classification."""
        try:
            response = await self.client.request(method=method, url=url, **kwargs)

            # Phân loại và xử lý Rate Limit tập trung
            if response.status_code == 429 and intercept_429:
                logger.warning("[%s] Upstream API rate limit exceeded immediately.", self.PROVIDER_NAME)
                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message="Rate limit exceeded. Request throttled by upstream.",
                    status_code=429,
                    raw_error_type="RateLimitExceeded",
                )

            # Chỉ ép validate Content-Type khi HTTP trả về thành công (200 OK)
            if response.status_code == 200:
                self._validate_response_content_type(response)

            if raise_for_status and response.status_code not in self._NON_ERROR_STATUSES:
                response.raise_for_status()

            return response

        except ProviderError:
            raise
        except httpx.TimeoutException as exc:
            logger.warning("[%s] Request timed out at network layer after %.1f seconds.", self.PROVIDER_NAME, self._timeout)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Request timed out threshold breached ({self._timeout}s).",
                status_code=408,
                raw_error_type="NetworkTimeout",
            ) from exc
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            # Gán nhãn lỗi thông minh (Semantic Error Typing) dựa trên HTTP Code
            error_type = "UpstreamClientError" if status_code < 500 else "UpstreamServerError"
            if status_code in (401, 403):
                error_type = "AuthenticationFailure"

            logger.error("[%s] Upstream rejected connection with HTTP %s.", self.PROVIDER_NAME, status_code)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=exc.response.text[:200],  # Truncate tránh log inflation
                status_code=status_code,
                raw_error_type=error_type,
            ) from exc
        except Exception as exc:
            # logger.exception giữ nguyên vẹn toàn bộ Stack Trace gốc (File name, line number) trong log system
            logger.exception("Unexpected structural crash from provider %s.", self.PROVIDER_NAME)
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Internal Component Exception: {type(exc).__name__} - {exc}",
                status_code=500,
                raw_error_type="InternalEngineCrash",
            ) from exc

    async def close(self) -> None:
        """Gracefully close the underlying HTTP client connection pool."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> BaseThreatProvider[T]:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()
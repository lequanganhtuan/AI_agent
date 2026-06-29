from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Generic type for provider-specific Pydantic response models.
T = TypeVar("T", bound=BaseModel)


class ThreatIntelInput(BaseModel):
    """
    Immutable Data Transfer Object (DTO) shared by all external
    Threat Intelligence providers.

    This object is produced from the Phase 1 ValidationResult and
    contains every field required by Phase 3 providers.
    """

    model_config = ConfigDict(frozen=True)

    normalized_url: str = Field(
        ...,
        description="Normalized URL generated during preprocessing.",
    )

    domain: str = Field(
        ...,
        description="Extracted root/full domain.",
    )

    ip_address: str | None = Field(
        default=None,
        description="Resolved IPv4/IPv6 address if available.",
    )

    cache_key: str | None = Field(
        default=None,
        description="Redis cache key shared across providers.",
    )


class ProviderError(Exception):
    """
    Unified exception raised by every Threat Intelligence provider.

    The orchestration layer only needs to catch ProviderError,
    regardless of which provider generated it.
    """

    def __init__(
        self,
        provider: str,
        message: str,
        status_code: int | None = None,
    ) -> None:

        self.provider = provider
        self.message = message
        self.status_code = status_code

        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.status_code is None:
            return f"[{self.provider}] {self.message}"

        return (
            f"[{self.provider}] "
            f"HTTP {self.status_code} - {self.message}"
        )


class BaseThreatProvider(ABC, Generic[T]):
    """
    Abstract base class for every external Threat Intelligence provider.

    Responsibilities
    ----------------
    - HTTP client lifecycle management
    - Connection pooling
    - Timeout handling
    - Exception isolation
    - Context manager support

    Responsibilities NOT included
    -----------------------------
    - Response parsing
    - Business logic
    - Cache handling
    - Retry strategy
    - Polling workflow
    """

    PROVIDER_NAME: str = "Base"

    def __init__(self, timeout: float) -> None:

        self._timeout = timeout

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
            ),
            headers={
                "User-Agent": (
                    "AI-URL-Fraud-Detection-System/2.0 "
                    "(Enterprise-Gateway)"
                )
            },
        )

    @property
    def client(self) -> httpx.AsyncClient:
        """
        Read-only access to the shared Async HTTP client.
        """
        return self._client

    @abstractmethod
    async def lookup(
        self,
        target: ThreatIntelInput,
    ) -> T:
        """
        Execute a provider-specific lookup request.

        Parameters
        ----------
        target:
            Input DTO shared across all providers.

        Returns
        -------
        Provider-specific Pydantic response model.
        """
        raise NotImplementedError

    @abstractmethod
    def parse_response(
        self,
        response: httpx.Response,
    ) -> T:
        """
        Convert the raw HTTP response into the provider-specific
        Pydantic response model.
        """
        raise NotImplementedError

    async def _safe_request(
        self,
        method: str,
        url: str,
        *,
        raise_for_status: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Execute an HTTP request with unified exception handling.

        Parameters
        ----------
        method:
            HTTP method.

        url:
            Target endpoint.

        raise_for_status:
            Whether HTTP status codes >=400 should automatically
            raise an exception.

        Returns
        -------
        httpx.Response

        Raises
        ------
        ProviderError
        """

        try:
            response = await self.client.request(
                method=method,
                url=url,
                **kwargs,
            )

            if response.status_code == 429:
                logger.warning(
                    "%s rate limit exceeded.",
                    self.PROVIDER_NAME,
                )

                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message="Rate limit exceeded.",
                    status_code=429,
                )

            if raise_for_status:
                response.raise_for_status()

            return response

        except ProviderError:
            raise

        except httpx.TimeoutException as exc:

            logger.warning(
                "%s request timed out after %.1f seconds.",
                self.PROVIDER_NAME,
                self._timeout,
            )

            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Request timeout.",
            ) from exc

        except httpx.HTTPStatusError as exc:

            logger.error(
                "%s returned HTTP %s.",
                self.PROVIDER_NAME,
                exc.response.status_code,
            )

            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=exc.response.text,
                status_code=exc.response.status_code,
            ) from exc

        except Exception as exc:

            logger.exception(
                "Unexpected error from provider %s.",
                self.PROVIDER_NAME,
            )

            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=str(exc),
            ) from exc

    async def close(self) -> None:
        """
        Close the underlying HTTP client.
        """
        await self.client.aclose()

    async def __aenter__(self) -> "BaseThreatProvider[T]":
        return self

    async def __aexit__(
        self,
        exc_type: Any,
        exc: Any,
        tb: Any,
    ) -> None:

        await self.close()

        return None
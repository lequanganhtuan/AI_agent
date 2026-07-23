import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

_http_client: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    """Returns the shared global httpx.AsyncClient instance with connection pooling."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(45.0, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            follow_redirects=True
        )
    return _http_client

async def close_http_client() -> None:
    """Closes the global httpx.AsyncClient instance cleanly on application shutdown."""
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        logger.info("[HTTPClient] Closing global httpx.AsyncClient connection pool...")
        await _http_client.aclose()
        _http_client = None

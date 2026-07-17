import time
import asyncio
import logging
from typing import Dict, List
from fastapi import Request, HTTPException, status

from src.core.settings import settings

logger = logging.getLogger(__name__)

# NOTE & WARNING:
# 1. Single-Worker Assumption: This is an in-memory rate limiter, meaning it is only correct when running on a 
#    single worker / single container deployment (e.g. --workers 1). If scaling horizontally or running multiple 
#    workers, this state will not be shared across processes. In such cases, state must be migrated to Redis.
# 2. Header Spoofing Risk: Reading IP headers (cf-connecting-ip, x-real-ip, x-forwarded-for) is only secure if 
#    Solution D (Network Isolation / Firewall) is active to prevent direct public access to the FastAPI port. 
#    Otherwise, attackers can spoof headers to bypass the rate limiter.
class InMemoryRateLimiter:
    """Thread-safe In-Memory Sliding Window Rate Limiter."""

    def __init__(self, requests_limit: int, window_seconds: int):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def is_rate_limited(self, key: str) -> bool:
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            # Clean up expired timestamps and get current active list
            if key in self._requests:
                self._requests[key] = [t for t in self._requests[key] if t > cutoff]
            else:
                self._requests[key] = []
            
            # If current request count is at or above the limit, rate limit the request
            if len(self._requests[key]) >= self.requests_limit:
                logger.warning(
                    f"[RateLimiter] Key {key} rate limited. Requests count: {len(self._requests[key])}/{self.requests_limit} in last {self.window_seconds}s"
                )
                return True
            
            # Register the new request
            self._requests[key].append(now)
            logger.info(
                f"[RateLimiter] Registered request for {key}. Count: {len(self._requests[key])}/{self.requests_limit} in last {self.window_seconds}s"
            )
            return False

# Initialize rate limiters using split configurations
analyze_limiter = InMemoryRateLimiter(
    requests_limit=settings.backend_rate_limit_analyze_requests,
    window_seconds=settings.backend_rate_limit_window
)

history_limiter = InMemoryRateLimiter(
    requests_limit=settings.backend_rate_limit_history_requests,
    window_seconds=settings.backend_rate_limit_window
)

def _get_client_ip(request: Request) -> str:
    """Helper to extract Client IP securely handling proxy/Cloudflare headers."""
    client_ip = (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or request.headers.get("x-forwarded-for")
    )
    if client_ip:
        return client_ip.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

async def analyze_rate_limit_dependency(request: Request):
    """Rate limit dependency for heavy URL scanning API (/api/analyze)."""
    client_ip = _get_client_ip(request)
    if await analyze_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many URL scan requests. Please try again later."
        )

async def history_rate_limit_dependency(request: Request):
    """Rate limit dependency for history endpoints (/api/history)."""
    client_ip = _get_client_ip(request)
    if await history_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many history requests. Please try again later."
        )

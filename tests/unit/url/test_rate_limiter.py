import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request, HTTPException, status

from src.core.security.rate_limiter import (
    InMemoryRateLimiter,
    analyze_rate_limit_dependency,
    history_rate_limit_dependency,
)

@pytest.mark.anyio
async def test_rate_limiter_sliding_window_limits():
    # Allow 2 requests per 10 seconds
    limiter = InMemoryRateLimiter(requests_limit=2, window_seconds=10)
    
    # 1st request -> allowed
    assert await limiter.is_rate_limited("test-ip") is False
    
    # 2nd request -> allowed
    assert await limiter.is_rate_limited("test-ip") is False
    
    # 3rd request -> rate limited
    assert await limiter.is_rate_limited("test-ip") is True
    
    # Different IP should be allowed
    assert await limiter.is_rate_limited("other-ip") is False

@pytest.mark.anyio
async def test_rate_limiter_expiration():
    limiter = InMemoryRateLimiter(requests_limit=1, window_seconds=5)
    
    with patch("time.time") as mock_time:
        # Time = 1000.0 -> 1st request allowed
        mock_time.return_value = 1000.0
        assert await limiter.is_rate_limited("expiry-ip") is False
        
        # Time = 1001.0 -> 2nd request rate limited
        mock_time.return_value = 1001.0
        assert await limiter.is_rate_limited("expiry-ip") is True
        
        # Time = 1006.0 (past 5s window) -> 3rd request allowed
        mock_time.return_value = 1006.0
        assert await limiter.is_rate_limited("expiry-ip") is False

@pytest.mark.anyio
async def test_rate_limit_dependency_extracts_ips():
    # Mock FastAPI Request
    mock_request = MagicMock(spec=Request)
    mock_request.client = MagicMock()
    mock_request.client.host = "127.0.0.1"
    
    # Test case 1: cf-connecting-ip header
    mock_request.headers = {"cf-connecting-ip": "1.2.3.4"}
    with patch("src.core.security.rate_limiter.analyze_limiter.is_rate_limited", AsyncMock(return_value=False)) as mock_check:
        await analyze_rate_limit_dependency(mock_request)
        mock_check.assert_called_once_with("1.2.3.4")

    # Test case 2: x-forwarded-for header (first IP in comma-separated list)
    mock_request.headers = {"x-forwarded-for": "5.6.7.8, 9.10.11.12"}
    with patch("src.core.security.rate_limiter.analyze_limiter.is_rate_limited", AsyncMock(return_value=False)) as mock_check:
        await analyze_rate_limit_dependency(mock_request)
        mock_check.assert_called_once_with("5.6.7.8")

    # Test case 3: fallback to request.client.host
    mock_request.headers = {}
    with patch("src.core.security.rate_limiter.analyze_limiter.is_rate_limited", AsyncMock(return_value=False)) as mock_check:
        await analyze_rate_limit_dependency(mock_request)
        mock_check.assert_called_once_with("127.0.0.1")

@pytest.mark.anyio
async def test_rate_limit_dependency_raises_429():
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {}
    mock_request.client.host = "12.34.56.78"
    
    with patch("src.core.security.rate_limiter.analyze_limiter.is_rate_limited", AsyncMock(return_value=True)):
        with pytest.raises(HTTPException) as exc_info:
            await analyze_rate_limit_dependency(mock_request)
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Too many URL scan requests" in exc_info.value.detail

@pytest.mark.anyio
async def test_history_rate_limit_dependency_raises_429():
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {}
    mock_request.client.host = "12.34.56.78"
    
    with patch("src.core.security.rate_limiter.history_limiter.is_rate_limited", AsyncMock(return_value=True)):
        with pytest.raises(HTTPException) as exc_info:
            await history_rate_limit_dependency(mock_request)
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Too many history requests" in exc_info.value.detail

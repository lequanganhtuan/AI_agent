from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock
from playwright.async_api import Error as PlaywrightError
from src.core.models import ValidationResult, PageSnapshot
from src.analyzers.url.dynamic_analysis.exceptions import NavigationError
from src.analyzers.url.dynamic_analysis.loader.page_loader import PageLoader
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserEngine

@pytest.mark.anyio
async def test_page_loader_success_mock():
    """Verify that PageLoader successfully calls page.goto and creates a correct PageSnapshot."""
    session = MagicMock()
    session.page = AsyncMock()
    
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_request = MagicMock()
    mock_request.url = "https://example.com/final"
    mock_request.redirected_from = None
    mock_response.request = mock_request
    session.page.goto.return_value = mock_response
    
    session.page.url = "https://example.com/final"
    session.page.title.return_value = "Example Title"
    session.page.content.return_value = "<html><body>Example</body></html>"
    
    validation_result = ValidationResult(
        valid=True,
        normalized_url="https://example.com/original"
    )
    
    loader = PageLoader()
    snapshot = await loader.load(session, validation_result)
    
    assert isinstance(snapshot, PageSnapshot)
    assert snapshot.original_url == "https://example.com/original"
    assert snapshot.final_url == "https://example.com/final"
    assert snapshot.status_code == 200
    assert snapshot.title == "Example Title"
    assert snapshot.html == "<html><body>Example</body></html>"
    assert snapshot.load_time_ms > 0
    
    session.page.goto.assert_called_once_with(
        "https://example.com/original",
        wait_until="load",
        timeout=30000
    )


@pytest.mark.anyio
async def test_page_loader_navigation_error_mock():
    """Verify that PageLoader catches Playwright Errors and wraps them in NavigationError."""
    session = MagicMock()
    session.page = AsyncMock()
    
    session.page.goto.side_effect = PlaywrightError("net::ERR_NAME_NOT_RESOLVED")
    
    validation_result = ValidationResult(
        valid=True,
        normalized_url="https://invalid-domain.test"
    )
    
    loader = PageLoader()
    
    with pytest.raises(NavigationError) as exc_info:
        await loader.load(session, validation_result)
        
    assert "Playwright navigation failed" in str(exc_info.value)


@pytest.mark.anyio
@pytest.mark.skip(reason="Requires live internet access and browser binary setup")
async def test_page_loader_live_integration():
    """Verify live integration of BrowserEngine and PageLoader on a real page."""
    engine = BrowserEngine()
    loader = PageLoader()
    
    validation_result = ValidationResult(
        valid=True,
        normalized_url="http://example.com"
    )
    
    async with engine.session() as session:
        snapshot = await loader.load(session, validation_result)
        assert snapshot.status_code == 200
        assert "Example Domain" in snapshot.title
        assert "example.com" in snapshot.final_url
        assert snapshot.load_time_ms > 0

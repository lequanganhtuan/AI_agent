from __future__ import annotations
import pytest
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserEngine, BrowserSession

@pytest.mark.anyio
async def test_browser_engine_creation_and_configs():
    """Verify that BrowserEngine initializes browser sessions with correct configurations from config.py."""
    engine = BrowserEngine()
    session = await engine.create_session()
    
    try:
        assert isinstance(session, BrowserSession)
        assert session.playwright is not None
        assert session.browser is not None
        assert session.context is not None
        assert session.page is not None
        
        # Verify viewport dimensions match DynamicAnalysisConfig configuration
        viewport = session.page.viewport_size
        assert viewport is not None
        assert viewport["width"] == engine.config.VIEWPORT_WIDTH
        assert viewport["height"] == engine.config.VIEWPORT_HEIGHT
        
        # Verify context configuration matches viewport configuration
        assert session.browser.is_connected() is True
    finally:
        # Safely shut down context lifecycle
        await session.close()


@pytest.mark.anyio
async def test_browser_engine_context_manager():
    """Verify context manager automatically opens and cleanly closes all Playwright resources."""
    engine = BrowserEngine()
    
    async with engine.session() as session:
        assert isinstance(session, BrowserSession)
        assert session.page is not None
        assert session.browser.is_connected() is True
        browser_ref = session.browser
        
    # After exiting the block, the browser must be closed
    assert browser_ref.is_connected() is False

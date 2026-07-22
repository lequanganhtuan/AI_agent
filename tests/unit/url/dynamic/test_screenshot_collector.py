from __future__ import annotations
import os
import shutil
import pytest
from unittest.mock import MagicMock, AsyncMock
from playwright.async_api import Error as PlaywrightError
from src.core.models import ScreenshotResult
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.exceptions import ScreenshotCaptureError
from src.analyzers.url.dynamic_analysis.screenshot.screenshot_collector import ScreenshotCollector

# Temporary test screenshot output directory
TEST_SCREENSHOT_DIR = "tests/unit/url/dynamic/temp_screenshots"

@pytest.fixture(autouse=True)
def cleanup_temp_screenshots():
    """Ensure temp directory is clean before and after each test."""
    if os.path.exists(TEST_SCREENSHOT_DIR):
        shutil.rmtree(TEST_SCREENSHOT_DIR)
    yield
    if os.path.exists(TEST_SCREENSHOT_DIR):
        shutil.rmtree(TEST_SCREENSHOT_DIR)


@pytest.mark.anyio
async def test_screenshot_collector_success():
    """Verify that ScreenshotCollector successfully captures screenshots and creates the missing directory."""
    session = MagicMock()
    page = AsyncMock()
    session.page = page

    # Mock page.screenshot to write a dummy file simulating playwright behavior
    async def mock_write_screenshot(*args, **kwargs):
        path = kwargs.get("path")
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(b"dummy_png_bytes")

    page.screenshot.side_effect = mock_write_screenshot

    config = DynamicAnalysisConfig()
    config.SCREENSHOT_DIRECTORY = TEST_SCREENSHOT_DIR
    config.SCREENSHOT_TYPE = "png"
    config.SCREENSHOT_FULL_PAGE = True

    collector = ScreenshotCollector(config=config)
    result = await collector.capture(session)

    # 1. Verify structured result
    assert isinstance(result, ScreenshotResult)
    from pathlib import Path
    assert Path(result.screenshot_path).parent == Path(TEST_SCREENSHOT_DIR)
    assert result.screenshot_path.endswith(".png")

    # 2. Verify file persistence and directory auto-creation
    assert os.path.exists(result.screenshot_path)
    with open(result.screenshot_path, "rb") as f:
        assert f.read() == b"dummy_png_bytes"

    # 3. Verify page.screenshot arguments passed correctly
    page.screenshot.assert_called_once_with(
        path=result.screenshot_path,
        full_page=True,
        type="png"
    )


@pytest.mark.anyio
async def test_screenshot_collector_no_overwriting():
    """Verify that multiple screenshot captures write to unique filenames."""
    session = MagicMock()
    page = AsyncMock()
    session.page = page

    # Mock writing dummy file
    async def mock_write_screenshot(*args, **kwargs):
        path = kwargs.get("path")
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(b"test")

    page.screenshot.side_effect = mock_write_screenshot

    config = DynamicAnalysisConfig()
    config.SCREENSHOT_DIRECTORY = TEST_SCREENSHOT_DIR
    collector = ScreenshotCollector(config=config)

    res1 = await collector.capture(session)
    res2 = await collector.capture(session)

    assert res1.screenshot_path != res2.screenshot_path
    assert os.path.exists(res1.screenshot_path)
    assert os.path.exists(res2.screenshot_path)


@pytest.mark.anyio
async def test_screenshot_collector_error_handling():
    """Verify that internal Playwright exceptions are mapped to ScreenshotCaptureError."""
    session = MagicMock()
    page = AsyncMock()
    session.page = page

    # Playwright exception
    page.screenshot.side_effect = PlaywrightError("Failed to grab frames")

    config = DynamicAnalysisConfig()
    config.SCREENSHOT_DIRECTORY = TEST_SCREENSHOT_DIR
    collector = ScreenshotCollector(config=config)

    with pytest.raises(ScreenshotCaptureError) as exc_info:
        await collector.capture(session)

    assert "Playwright screenshot failed" in str(exc_info.value)

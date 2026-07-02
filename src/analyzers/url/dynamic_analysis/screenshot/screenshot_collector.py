from __future__ import annotations
import uuid
import logging
from pathlib import Path
from playwright.async_api import Error as PlaywrightError
from src.core.models import ScreenshotResult
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserSession
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.exceptions import ScreenshotCaptureError

logger = logging.getLogger(__name__)

class ScreenshotCollector:
    """Collector responsible for capturing visual screenshots of page loads."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    async def capture(self, session: BrowserSession) -> ScreenshotResult:
        """
        Capture a full page screenshot using the active BrowserSession.

        Args:
            session: Active BrowserSession.

        Returns:
            ScreenshotResult: Data containing the relative screenshot storage path.

        Raises:
            ScreenshotCaptureError: Wraps underlying Playwright capture or system writing errors.
        """
        page = session.page
        if not page:
            raise ScreenshotCaptureError("Failed to capture screenshot: Active page is None.")

        # Ensure screenshot directory exists using pathlib
        screenshot_dir = Path(self.config.SCREENSHOT_DIRECTORY)
        try:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.exception("[ScreenshotCollector] Failed to create screenshot directory: %s", screenshot_dir)
            raise ScreenshotCaptureError(f"Failed to create screenshot directory: {str(e)}") from e

        # Generate unique filename
        filename = f"{uuid.uuid4().hex}.{self.config.SCREENSHOT_TYPE}"
        screenshot_path = screenshot_dir / filename

        # Set up screenshot arguments
        kwargs = {
            "path": str(screenshot_path),
            "full_page": self.config.SCREENSHOT_FULL_PAGE,
            "type": self.config.SCREENSHOT_TYPE
        }

        if self.config.SCREENSHOT_TYPE == "jpeg" and self.config.SCREENSHOT_QUALITY is not None:
            kwargs["quality"] = self.config.SCREENSHOT_QUALITY

        try:
            await page.screenshot(**kwargs)
            return ScreenshotResult(screenshot_path=str(screenshot_path))
        except PlaywrightError as e:
            logger.exception("[ScreenshotCollector] Playwright error during screenshot capture")
            raise ScreenshotCaptureError(f"Playwright screenshot failed: {str(e)}") from e
        except Exception as e:
            logger.exception("[ScreenshotCollector] Unexpected error during screenshot capture")
            raise ScreenshotCaptureError(f"Unexpected screenshot capture failure: {str(e)}") from e

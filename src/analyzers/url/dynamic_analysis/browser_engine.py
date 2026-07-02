from __future__ import annotations
import logging
from typing import Any, AsyncIterator
import contextlib
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass(slots=True)
class BrowserSession:
    """Represents a managed browser session containing the browser, context, and page instances."""
    playwright: Playwright
    browser: Browser
    context: BrowserContext
    page: Page

    async def close(self) -> None:
        """Safely close all components of the session in reverse order."""
        try:
            if self.page:
                await self.page.close()
        except Exception as e:
            logger.warning("[BrowserSession] Error closing page: %s", e)

        try:
            if self.context:
                await self.context.close()
        except Exception as e:
            logger.warning("[BrowserSession] Error closing context: %s", e)

        try:
            if self.browser:
                await self.browser.close()
        except Exception as e:
            logger.warning("[BrowserSession] Error closing browser: %s", e)

        try:
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.warning("[BrowserSession] Error stopping playwright: %s", e)

    async def __aenter__(self) -> BrowserSession:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

class BrowserEngine:
    """Engine responsible for initializing Playwright and setting up BrowserSessions."""

    def __init__(self, config: DynamicAnalysisConfig | type[DynamicAnalysisConfig] | None = None) -> None:
        if config is None:
            self.config = DynamicAnalysisConfig()
        elif isinstance(config, type):
            self.config = config()
        else:
            self.config = config

    async def create_session(self) -> BrowserSession:
        """Initialize Playwright, launch Chromium, configure context, and open a page."""
        playwright = None
        browser = None
        context = None
        page = None
        try:
            playwright = await async_playwright().start()

            # Browser launch args
            args = []
            if self.config.NO_SANDBOX:
                args.append("--no-sandbox")

            browser = await playwright.chromium.launch(
                headless=self.config.HEADLESS,
                args=args
            )

            # BrowserContext configuration
            context = await browser.new_context(
                viewport={
                    "width": self.config.VIEWPORT_WIDTH,
                    "height": self.config.VIEWPORT_HEIGHT
                },
                user_agent=self.config.USER_AGENT,
                ignore_https_errors=self.config.IGNORE_HTTPS_ERRORS
            )

            # Set default timeout
            context.set_default_timeout(self.config.TIMEOUT_MS)
            context.set_default_navigation_timeout(self.config.TIMEOUT_MS)

            page = await context.new_page()

            return BrowserSession(playwright, browser, context, page)

        except Exception:
            logger.exception("[BrowserEngine] Failed to initialize browser session")
            # Safe cleanup of partially initialized resources
            try:
                if page:
                    await page.close()
            except Exception:
                pass
            try:
                if context:
                    await context.close()
            except Exception:
                pass
            try:
                if browser:
                    await browser.close()
            except Exception:
                pass
            try:
                if playwright:
                    await playwright.stop()
            except Exception:
                pass
            raise

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[BrowserSession]:
        """Async context manager for yielding a managed BrowserSession and closing it automatically."""
        session = await self.create_session()
        try:
            yield session
        finally:
            await session.close()

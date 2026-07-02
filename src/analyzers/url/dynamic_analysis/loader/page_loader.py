from __future__ import annotations
import time
import logging
from playwright.async_api import Error as PlaywrightError
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserSession
from src.core.models import ValidationResult, PageSnapshot
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.exceptions import NavigationError

logger = logging.getLogger(__name__)

class PageLoader:
    """Loader responsible for navigating to URLs and capturing main document snapshots."""

    def __init__(self, config: DynamicAnalysisConfig | type[DynamicAnalysisConfig] | None = None) -> None:
        if config is None:
            self.config = DynamicAnalysisConfig()
        elif isinstance(config, type):
            self.config = config()
        else:
            self.config = config

    async def load(
        self,
        session: BrowserSession,
        validation_result: ValidationResult
    ) -> PageSnapshot:
        """
        Navigate to a URL using Playwright and capture the Main Document's response.
        
        Args:
            session: The active BrowserSession.
            validation_result: ValidationResult containing the normalized URL.
            
        Returns:
            PageSnapshot: Captures original URL, final destination URL, status, title, HTML source, and load time.
            
        Raises:
            NavigationError: Wraps any Playwright-level or underlying network/SSL/DNS errors.
        """
        url = validation_result.normalized_url or ""
        if not url:
            raise NavigationError("ValidationResult does not contain a valid URL.")

        start_time = time.perf_counter()
        try:
            wait_until_strategy = self.config.WAIT_UNTIL_STRATEGY
            
            # Navigate to the target page
            response = await session.page.goto(
                url,
                wait_until=wait_until_strategy,
                timeout=self.config.TIMEOUT_MS
            )

            load_time_ms = (time.perf_counter() - start_time) * 1000.0

            # If response is None, page failed to return document response (e.g. redirected to non-HTTP protocol)
            if response is None:
                raise NavigationError(f"Failed to load page {url}: Main document response is None.")

            # Collect final URL, title, html source and status code
            final_url = session.page.url
            status_code = response.status
            title = await session.page.title()
            html = await session.page.content()

            # Extract redirect chain chronologically from Playwright response request history
            redirect_chain: list[str] = []
            current_req = response.request
            while current_req:
                redirect_chain.append(current_req.url)
                current_req = current_req.redirected_from
            redirect_chain.reverse()

            return PageSnapshot(
                original_url=validation_result.normalized_url or url,
                final_url=final_url,
                status_code=status_code,
                title=title,
                html=html,
                load_time_ms=load_time_ms,
                redirect_chain=redirect_chain
            )

        except PlaywrightError as e:
            # Wrap standard Playwright exceptions as a unified Dynamic Analysis exception
            logger.exception("[PageLoader] Playwright error during navigation to %s", url)
            raise NavigationError(f"Playwright navigation failed: {str(e)}") from e
        except NavigationError:
            # Re-raise already unified NavigationErrors directly
            raise
        except Exception as e:
            logger.exception("[PageLoader] Unexpected error during navigation to %s", url)
            raise NavigationError(f"Unexpected navigation error: {str(e)}") from e

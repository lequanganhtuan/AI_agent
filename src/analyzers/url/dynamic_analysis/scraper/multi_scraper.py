from __future__ import annotations
import asyncio
import logging
import time
import base64
from typing import Any
import httpx
from src.core.settings import settings

logger = logging.getLogger(__name__)

# Số ký tự tối đa của response body được đưa vào log lỗi (tránh log quá dài)
ERROR_BODY_PREVIEW_LIMIT = 500


class ScraperAPIError(Exception):
    """Base exception for scraping API errors."""
    pass

class QuotaExceededError(ScraperAPIError):
    """Raised when an API provider quota is fully exhausted."""
    pass

class AllProvidersExhaustedError(ScraperAPIError):
    """Raised when all configured scraping providers are unavailable or out of quota."""
    pass


class MultiScraperClient:
    """
    Asynchronous, thread-safe client that distributes web scraping requests
    across Scrape.do, ScraperAPI, and ScrapingAnt using a Round-Robin algorithm
    with per-provider concurrency control (asyncio.Semaphore) and active failover.
    Supports a dynamic cooldown mechanism to temporarily disable failing or exhausted providers.
    """

    def __init__(self) -> None:
        # Initialize providers with their respective tokens, semaphores, endpoints, and cooldown states.
        self.providers = {
            "scrape_do": {
                "token": settings.scrape_do_token,
                "semaphore": asyncio.Semaphore(2),
                "endpoint": "https://api.scrape.do",
                "disabled_until": 0.0
            },
            "scraper_api": {
                "token": settings.scraper_api_key,
                "semaphore": asyncio.Semaphore(2),
                "endpoint": "https://api.scraperapi.com",
                "disabled_until": 0.0
            },
            "scraping_ant": {
                "token": settings.scraping_ant_api_key,
                "semaphore": asyncio.Semaphore(2),
                "endpoint": "https://api.scrapingant.com/v2/general",
                "disabled_until": 0.0
            }
        }
        
        # Determine valid configured providers
        self.configured_keys = [
            k for k, v in self.providers.items()
            if v["token"] and not v["token"].startswith("your_")
        ]
        
        # Round-robin tracking index
        self.current_index = 0
        logger.info(f"[MultiScraperClient] Initialized with configured providers: {self.configured_keys}")

    def _get_active_keys(self) -> list[str]:
        """Returns the list of configured providers that are currently active (not in cooldown)."""
        now = time.time()
        return [
            k for k in self.configured_keys
            if now >= self.providers[k]["disabled_until"]
        ]

    # Main stream
    async def scrape(self, target_url: str) -> dict[str, Any]:
        """
        Scrapes the target URL using the next available active provider.
        Supports active failover: if a provider fails or is out of quota, it goes into
        cooldown (temporary lockout), and the request is retried on others.
        """
        active_keys = self._get_active_keys()
        if not active_keys:
            raise AllProvidersExhaustedError("All scraping API providers are currently in cooldown or unconfigured.")

        # Round-Robin selection over active keys
        provider_name = active_keys[self.current_index % len(active_keys)]
        self.current_index = (self.current_index + 1) % len(active_keys)

        provider_config = self.providers[provider_name]
        logger.info(f"[MultiScraperClient] Selected active provider '{provider_name}' for URL: {target_url}")

        # Limit concurrency using the provider's semaphore
        async with provider_config["semaphore"]:
            try:
                result = await self._execute_scrape(provider_name, provider_config, target_url)
                return result
            except QuotaExceededError as e:
                # Quota limit exceeded: Cooldown for 12 hours
                cooldown_time = 12 * 3600
                self.providers[provider_name]["disabled_until"] = time.time() + cooldown_time
                logger.warning(
                    f"[MultiScraperClient] Provider '{provider_name}' exhausted quota: {str(e)}. "
                    f"Cooling down for 12 hours."
                )
                # Retry recursively with remaining active providers
                return await self.scrape(target_url)
            except ScraperAPIError as e:
                # General API or connection error: Cooldown for 5 minutes (300 seconds)
                cooldown_time = 300
                self.providers[provider_name]["disabled_until"] = time.time() + cooldown_time
                logger.warning(
                    f"[MultiScraperClient] Provider '{provider_name}' failed: {str(e)}. "
                    f"Cooling down for 5 minutes."
                )
                # Retry recursively with remaining active providers
                return await self.scrape(target_url)

    # Call specific API
    async def _execute_scrape(self, provider_name: str, config: dict, target_url: str) -> dict[str, Any]:
        """Executes the HTTP scraping request for a specific provider."""
        async with httpx.AsyncClient(timeout=45.0) as client:
            try:
                if provider_name == "scrape_do":
                    params = {
                        "token": config["token"],
                        "url": target_url,
                        "screenshot": "true",
                        "render": "true",
                        "returnJSON": "true"
                    }
                    response = await client.get(config["endpoint"], params=params)

                    if response.status_code in (403, 429):
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise QuotaExceededError(
                            f"Scrape.do quota limit exceeded (HTTP {response.status_code}): {body_preview}"
                        )
                    elif response.status_code != 200:
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise ScraperAPIError(
                            f"Scrape.do returned HTTP {response.status_code}: {body_preview}"
                        )

                    try:
                        res_json = response.json()
                    except Exception as e:
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise ScraperAPIError(
                            f"Scrape.do returned invalid/non-JSON response: {str(e)} | body: '{body_preview}'"
                        )

                    html = res_json.get("content", "")
                    if not html:
                        raise ScraperAPIError(
                            f"Scrape.do returned an empty 'content' field. "
                            f"Raw response: {str(res_json)[:ERROR_BODY_PREVIEW_LIMIT]}"
                        )

                    screenshot_bytes = b""
                    screenshots = res_json.get("screenShots", [])
                    if screenshots and isinstance(screenshots, list):
                        first_screenshot = screenshots[0]
                        if isinstance(first_screenshot, dict):
                            screenshot_b64 = first_screenshot.get("image", "")
                            if screenshot_b64:
                                try:
                                    screenshot_bytes = base64.b64decode(screenshot_b64)
                                except Exception as e:
                                    logger.warning(f"[Scrape.do] Failed to decode base64 screenshot: {str(e)}")

                    return {
                        "html": html,
                        "screenshot": screenshot_bytes,
                        "redirects": [target_url]  # Default hop
                    }

                elif provider_name == "scraper_api":
                    params = {
                        "api_key": config["token"],
                        "url": target_url,
                        "render": "true"
                    }
                    response = await client.get(config["endpoint"], params=params)

                    if response.status_code in (403, 429):
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise QuotaExceededError(
                            f"ScraperAPI quota limit or rate limit exceeded (HTTP {response.status_code}): {body_preview}"
                        )
                    elif response.status_code != 200:
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise ScraperAPIError(
                            f"ScraperAPI returned HTTP {response.status_code}: {body_preview}"
                        )

                    html = response.text
                    # ScraperAPI returns headers with redirect information
                    final_url = response.headers.get("x-final-url", target_url)
                    screenshot_bytes = b""
                    
                    return {
                        "html": html,
                        "screenshot": screenshot_bytes,
                        "redirects": [target_url, final_url] if final_url != target_url else [target_url]
                    }

                elif provider_name == "scraping_ant":
                    # ScrapingAnt JS rendering API request
                    params = {
                        "api_key": config["token"],
                        "url": target_url,
                        "browser": "true"
                    }
                    response = await client.get(config["endpoint"], params=params)

                    if response.status_code in (403, 429):
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise QuotaExceededError(
                            f"ScrapingAnt quota limit exceeded (HTTP {response.status_code}): {body_preview}"
                        )
                    elif response.status_code != 200:
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise ScraperAPIError(
                            f"ScrapingAnt returned HTTP {response.status_code}: {body_preview}"
                        )

                    # ScrapingAnt JSON response format contains the HTML and screenshot details.
                    # An empty/invalid body (or valid JSON with no "html" field) must NOT be
                    # treated as a successful scrape — raise so the caller can fail over
                    # to another provider instead of silently returning empty content.
                    try:
                        res_json = response.json()
                    except Exception as e:
                        body_preview = response.text[:ERROR_BODY_PREVIEW_LIMIT]
                        raise ScraperAPIError(
                            f"ScrapingAnt returned invalid/non-JSON response: {str(e)} | body: '{body_preview}'"
                        )

                    html = res_json.get("html", "")
                    if not html:
                        raise ScraperAPIError(
                            f"ScrapingAnt returned an empty 'html' field. "
                            f"Raw response: {str(res_json)[:ERROR_BODY_PREVIEW_LIMIT]}"
                        )

                    # ScrapingAnt can return screenshot as base64
                    screenshot_b64 = res_json.get("screenshot", "")
                    try:
                        screenshot_bytes = base64.b64decode(screenshot_b64) if screenshot_b64 else b""
                    except Exception as e:
                        # Don't fail the whole scrape just because the screenshot couldn't be decoded
                        logger.warning(f"[ScrapingAnt] Failed to decode base64 screenshot: {str(e)}")
                        screenshot_bytes = b""

                    return {
                        "html": html,
                        "screenshot": screenshot_bytes,
                        "redirects": [target_url]
                    }

            except httpx.RequestError as e:
                raise ScraperAPIError(f"Network error communicating with {provider_name}: {str(e)}")
            except Exception as e:
                if isinstance(e, ScraperAPIError):
                    raise e
                raise ScraperAPIError(f"Unexpected error in provider {provider_name}: {str(e)}")
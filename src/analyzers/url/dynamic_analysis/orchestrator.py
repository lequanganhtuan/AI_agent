from __future__ import annotations
import time
import logging
import os
import asyncio
import hashlib
from src.core.models import (
    AnalysisContext,
    DynamicAnalysisResult,
    PageSnapshot,
    NetworkAnalysis
)
from src.core.settings import settings
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.scraper.multi_scraper import MultiScraperClient
from src.core.database.storage_repository import StorageRepository
from src.analyzers.url.dynamic_analysis.redirect.redirect_analyzer import RedirectAnalyzer
from src.analyzers.url.dynamic_analysis.dom.dom_analyzer import DOMAnalyzer
from src.analyzers.url.dynamic_analysis.signal.dynamic_signal_generator import DynamicSignalGenerator
from src.analyzers.url.dynamic_analysis.risk.dynamic_risk_calculator import DynamicRiskCalculator
from src.analyzers.url.dynamic_analysis.risk.dynamic_summary_generator import DynamicSummaryGenerator
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain

logger = logging.getLogger(__name__)

class DynamicAnalysisOrchestrator:
    """Orchestrator coordinating Giai đoạn 4 Dynamic Analysis pipeline lifecycle using external APIs."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()
        self.scraper_client = MultiScraperClient()
        self.storage_repo = StorageRepository()
        self.redirect_analyzer = RedirectAnalyzer()
        self.dom_analyzer = DOMAnalyzer(config=self.config)
        self.signal_generator = DynamicSignalGenerator(config=self.config)
        self.risk_calculator = DynamicRiskCalculator()
        self.summary_generator = DynamicSummaryGenerator()

    def _create_failed_result(self, context: AnalysisContext) -> DynamicAnalysisResult:
        """Consolidate failed result generation and context updates."""
        result = DynamicAnalysisResult(status="failed")
        context.dynamic = result
        return result

    async def analyze(self, context: AnalysisContext) -> DynamicAnalysisResult:
        """
        Orchestrate the active dynamic analysis collection and evaluation pipeline.

        Args:
            context: The current AnalysisContext.

        Returns:
            DynamicAnalysisResult: Aggregated result model.
        """
        normalized_url = context.validation.normalized_url or ""
        if not normalized_url:
            logger.error("[DynamicAnalysisOrchestrator] Input context has no normalized URL.")
            return self._create_failed_result(context)

        loop = asyncio.get_running_loop()

        # 1. Scraping using the multi-provider client (Round-Robin & Concurrency-controlled)
        try:
            start_time = time.perf_counter()
            scrape_res = await self.scraper_client.scrape(normalized_url)
            load_time_ms = (time.perf_counter() - start_time) * 1000
            logger.info("[DynamicAnalysisOrchestrator] Scraper API latency: %.2f ms", load_time_ms)
        except Exception as e:
            logger.error(f"[DynamicAnalysisOrchestrator] Scraping failed for {normalized_url}: {str(e)}")
            return self._create_failed_result(context)

        # Ensure consistent and unique cache_key fallback to prevent screenshot overrides on storage
        cache_key = getattr(context.validation, "cache_key", None)
        if not cache_key:
            hash_obj = hashlib.md5(f"{normalized_url}_{time.time()}".encode("utf-8"))
            cache_key = f"rand_{hash_obj.hexdigest()}"
        
        # Clean colons to prevent Windows local filesystem errors in the Storage Emulator
        safe_cache_key = cache_key.replace(":", "_")

        # 2. Upload screenshot to Firebase Storage if available
        screenshot_path = None
        screenshot_bytes = scrape_res.get("screenshot", b"")
        
        # Fallback to WordPress mshots if Scraping API returned no screenshot (due to free plan limits)
        if not screenshot_bytes:
            logger.info("[DynamicAnalysisOrchestrator] Scraping API returned no screenshot. Trying fallback WordPress mshots API...")
            try:
                import urllib.parse
                import httpx
                encoded_url = urllib.parse.quote(normalized_url)
                mshots_url = f"https://s0.wp.com/mshots/v1/{encoded_url}?w=1024"
                
                limits = httpx.Limits(max_keepalive_connections=0, max_connections=5)
                async with httpx.AsyncClient(timeout=20.0, limits=limits) as client:
                    mshots_res = await client.get(mshots_url, follow_redirects=True)
                    if mshots_res.status_code == 200:
                        # Check length to verify it's a valid image
                        if len(mshots_res.content) > 1000:
                            screenshot_bytes = mshots_res.content
                            logger.info("[DynamicAnalysisOrchestrator] Successfully fetched fallback screenshot from WordPress mshots API.")
            except Exception as mshot_err:
                logger.warning(f"[DynamicAnalysisOrchestrator] WordPress mshots fallback failed: {str(mshot_err)}")

        if screenshot_bytes:
            try:
                start_time = time.perf_counter()
                screenshot_path = await self.storage_repo.upload_screenshot(safe_cache_key, screenshot_bytes)
                screenshot_time_ms = (time.perf_counter() - start_time) * 1000
                logger.info("[DynamicAnalysisOrchestrator] Screenshot Storage Upload latency: %.2f ms", screenshot_time_ms)
            except Exception:
                logger.exception("[DynamicAnalysisOrchestrator] Failed to upload screenshot to Storage")
                screenshot_path = None

        # 3. Create a snapshot mock compat for analyzers
        redirect_chain = scrape_res.get("redirects", [normalized_url])
        final_url = redirect_chain[-1] if redirect_chain else normalized_url
        html_content = scrape_res.get("html", "")

        # Extract page title dynamically from HTML via regex
        import re
        title_match = re.search(r"<title>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else "No Title"

        snapshot = PageSnapshot(
            original_url=normalized_url,
            final_url=final_url,
            status_code=200,
            title=title,
            html=html_content,
            load_time_ms=load_time_ms,
            redirect_chain=redirect_chain
        )

        # 4. Analyze redirect chains and DOM in Thread Pool (CPU-bound HTML parse offloading)
        start_time = time.perf_counter()
        redirect_res = await loop.run_in_executor(None, self.redirect_analyzer.analyze, snapshot)
        redirect_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info("[DynamicAnalysisOrchestrator] Redirect Analysis latency: %.2f ms", redirect_time_ms)

        start_time = time.perf_counter()
        dom_res = await loop.run_in_executor(None, self.dom_analyzer.analyze, snapshot)
        dom_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info("[DynamicAnalysisOrchestrator] DOM Parsing latency: %.2f ms", dom_time_ms)

        # 5. Mock network metrics (API scrapers do not return browser network packet logs)
        network_res = NetworkAnalysis()

        # 6. Evaluate signals, composite risk levels, and summaries
        start_time = time.perf_counter()
        signals = self.signal_generator.generate(redirect_res, dom_res, network_res)
        signal_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info("[DynamicAnalysisOrchestrator] Signal Generation processing latency: %.2f ms", signal_time_ms)

        # Trusted domain validation: check both original input domain and final redirected domain
        is_trusted = False
        from src.analyzers.url.static.config import BrandConfig
        
        # Check original domain
        components = getattr(context.validation, "components", None)
        orig_domain = getattr(components, "full_domain", "") if components else ""
        if orig_domain and any(orig_domain == trusted or orig_domain.endswith("." + trusted) for trusted in BrandConfig.TRUSTED_PLATFORMS):
            is_trusted = True
            
        # Check final redirected domain
        final_domain = get_apex_domain(final_url)
        if final_domain and any(final_domain == trusted or final_domain.endswith("." + trusted) for trusted in BrandConfig.TRUSTED_PLATFORMS):
            is_trusted = True

        if context.static and getattr(context.static, "brand", None):
            if getattr(context.static.brand, "legitimate_domain_match", False):
                is_trusted = True

        # Reset timer before risk calculation for accurate latency tracking
        start_time = time.perf_counter()
        risk_res = self.risk_calculator.calculate(signals, is_trusted=is_trusted)
        risk_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info("[DynamicAnalysisOrchestrator] Risk Calculation latency: %.2f ms", risk_time_ms)

        summary = self.summary_generator.generate(risk_res)

        # 7. Construct result
        result = DynamicAnalysisResult(
            status="completed",
            screenshot_path=screenshot_path,
            redirects=redirect_res,
            dom=dom_res,
            network=network_res,
            signals=signals,
            risk=risk_res,
            summary=summary
        )
        
        # Save dynamic HTML to local filesystem for debug/diagnostic ONLY in debug mode to prevent leaks or OOM
        if settings.debug and html_content:
            def _write_debug_html():
                os.makedirs("artifacts/scans", exist_ok=True)
                safe_key = cache_key.replace(":", "_")
                # Using a sandbox-safe structure, ensure this dir is not served directly
                with open(f"artifacts/scans/{safe_key}.html", "w", encoding="utf-8") as f:
                    f.write(html_content)
            
            try:
                await loop.run_in_executor(None, _write_debug_html)
            except Exception as e:
                logger.error(f"Failed to save dynamic HTML to cache file: {str(e)}")

        context.dynamic = result
        return result

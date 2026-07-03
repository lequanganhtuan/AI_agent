from __future__ import annotations
import time
import logging
from src.core.models import (
    AnalysisContext,
    DynamicAnalysisResult
)
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserEngine
from src.analyzers.url.dynamic_analysis.loader.page_loader import PageLoader
from src.analyzers.url.dynamic_analysis.redirect.redirect_analyzer import RedirectAnalyzer
from src.analyzers.url.dynamic_analysis.dom.dom_analyzer import DOMAnalyzer
from src.analyzers.url.dynamic_analysis.network.network_analyzer import NetworkAnalyzer
from src.analyzers.url.dynamic_analysis.screenshot.screenshot_collector import ScreenshotCollector
from src.analyzers.url.dynamic_analysis.signal.dynamic_signal_generator import DynamicSignalGenerator
from src.analyzers.url.dynamic_analysis.risk.dynamic_risk_calculator import DynamicRiskCalculator
from src.analyzers.url.dynamic_analysis.risk.dynamic_summary_generator import DynamicSummaryGenerator
from src.analyzers.url.dynamic_analysis.exceptions import (
    DynamicAnalysisError,
    NavigationError,
    ScreenshotCaptureError
)

logger = logging.getLogger(__name__)

class DynamicAnalysisOrchestrator:
    """Orchestrator coordinating Giai đoạn 4 Dynamic Analysis pipeline lifecycle."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()
        self.browser_engine = BrowserEngine(config=self.config)
        self.page_loader = PageLoader(config=self.config)
        self.redirect_analyzer = RedirectAnalyzer()
        self.dom_analyzer = DOMAnalyzer(config=self.config)
        self.network_analyzer = NetworkAnalyzer(config=self.config)
        self.screenshot_collector = ScreenshotCollector(config=self.config)
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

        async with self.browser_engine.session() as session:
            try:
                # 1. Start network logs logging before navigation
                self.network_analyzer.start_capture(session, normalized_url)

                # 2. Load primary page document catching only domain-mapped exceptions
                try:
                    start_time = time.perf_counter()
                    snapshot = await self.page_loader.load(session, context.validation)
                    load_time_ms = (time.perf_counter() - start_time) * 1000
                    logger.info("[DynamicAnalysisOrchestrator] Page Loading latency: %.2f ms", load_time_ms)
                except NavigationError:
                    logger.exception("[DynamicAnalysisOrchestrator] Navigation error for %s", normalized_url)
                    # Gracefully finalize capture even on fail
                    self.network_analyzer.stop_capture()
                    return self._create_failed_result(context)

                # 3. Post-load visual screenshot capture catching only specific errors
                try:
                    start_time = time.perf_counter()
                    screenshot_res = await self.screenshot_collector.capture(session)
                    screenshot_path = screenshot_res.screenshot_path
                    screenshot_time_ms = (time.perf_counter() - start_time) * 1000
                    logger.info("[DynamicAnalysisOrchestrator] Screenshot Capture latency: %.2f ms", screenshot_time_ms)
                except ScreenshotCaptureError:
                    logger.exception("[DynamicAnalysisOrchestrator] Visual screenshot capture failed")
                    screenshot_path = None

                # 4. Analyze redirect chains and DOM
                start_time = time.perf_counter()
                redirect_res = self.redirect_analyzer.analyze(snapshot)
                redirect_time_ms = (time.perf_counter() - start_time) * 1000
                logger.info("[DynamicAnalysisOrchestrator] Redirect Analysis latency: %.2f ms", redirect_time_ms)

                start_time = time.perf_counter()
                dom_res = self.dom_analyzer.analyze(snapshot)
                dom_time_ms = (time.perf_counter() - start_time) * 1000
                logger.info("[DynamicAnalysisOrchestrator] DOM Parsing latency: %.2f ms", dom_time_ms)

                # 5. Stop network capture
                start_time = time.perf_counter()
                network_res = self.network_analyzer.stop_capture()
                network_time_ms = (time.perf_counter() - start_time) * 1000
                logger.info("[DynamicAnalysisOrchestrator] Network Capture overhead/processing latency: %.2f ms", network_time_ms)

                # 6. Evaluate signals, composite risk levels, and summaries
                start_time = time.perf_counter()
                signals = self.signal_generator.generate(redirect_res, dom_res, network_res)
                signal_time_ms = (time.perf_counter() - start_time) * 1000
                logger.info("[DynamicAnalysisOrchestrator] Signal Generation processing latency: %.2f ms", signal_time_ms)

                is_trusted = False
                if context.static and getattr(context.static, "brand", None):
                    if getattr(context.static.brand, "legitimate_domain_match", False):
                        is_trusted = True
                    from src.analyzers.url.static.config import BrandConfig
                    components = getattr(context.validation, "components", None)
                    domain = getattr(components, "full_domain", "") if components else ""
                    if domain and any(domain == trusted or domain.endswith("." + trusted) for trusted in BrandConfig.TRUSTED_PLATFORMS):
                        is_trusted = True

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
                context.dynamic = result
                return result

            except Exception:
                logger.exception("[DynamicAnalysisOrchestrator] High level orchestrator failure")
                # Safety capture termination using public API check
                if self.network_analyzer.is_capturing():
                    self.network_analyzer.stop_capture()
                return self._create_failed_result(context)

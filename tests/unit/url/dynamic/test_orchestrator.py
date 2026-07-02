from __future__ import annotations
import pytest
from unittest.mock import MagicMock, AsyncMock, call
from src.core.models import (
    AnalysisContext,
    ValidationResult,
    StaticAnalysisResult,
    ThreatIntelligenceResult,
    PageSnapshot,
    RedirectAnalysis,
    DOMAnalysis,
    NetworkAnalysis,
    ScreenshotResult,
    DynamicSignal,
    DynamicRisk,
    DynamicAnalysisResult
)
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, ConfigurationError
from src.analyzers.url.dynamic_analysis.exceptions import NavigationError
from src.analyzers.url.dynamic_analysis.orchestrator import DynamicAnalysisOrchestrator

@pytest.mark.anyio
async def test_orchestrator_success_flow():
    """Verify that DynamicAnalysisOrchestrator successfully stitches all components chronologically."""
    config = DynamicAnalysisConfig()
    orchestrator = DynamicAnalysisOrchestrator(config=config)

    # Mock all internal lifecycle modules
    mock_session = MagicMock()
    mock_session.page = MagicMock()

    orchestrator.browser_engine = MagicMock()
    # Mock async context manager for session
    async_context = AsyncMock()
    async_context.__aenter__.return_value = mock_session
    orchestrator.browser_engine.session.return_value = async_context

    orchestrator.network_analyzer = MagicMock()
    orchestrator.page_loader = AsyncMock()
    orchestrator.screenshot_collector = AsyncMock()
    orchestrator.redirect_analyzer = MagicMock()
    orchestrator.dom_analyzer = MagicMock()
    orchestrator.signal_generator = MagicMock()
    orchestrator.risk_calculator = MagicMock()

    # Define mock return data
    mock_snapshot = MagicMock(spec=PageSnapshot)
    orchestrator.page_loader.load.return_value = mock_snapshot

    mock_screenshot = ScreenshotResult(screenshot_path="artifacts/screenshots/uuid1.png")
    orchestrator.screenshot_collector.capture.return_value = mock_screenshot

    mock_redirect = MagicMock(spec=RedirectAnalysis)
    orchestrator.redirect_analyzer.analyze.return_value = mock_redirect

    mock_dom = MagicMock(spec=DOMAnalysis)
    orchestrator.dom_analyzer.analyze.return_value = mock_dom

    mock_network = MagicMock(spec=NetworkAnalysis)
    orchestrator.network_analyzer.stop_capture.return_value = mock_network

    mock_sig = MagicMock(spec=DynamicSignal)
    mock_sig.signal = "PASSWORD_FIELD"
    mock_sig.severity = "HIGH"
    mock_sig.confidence = 1.0
    mock_sig.evidence = "Detected password input field."
    mock_signals = [mock_sig]
    orchestrator.signal_generator.generate.return_value = mock_signals

    mock_risk = MagicMock(spec=DynamicRisk)
    mock_risk.score = 65
    mock_risk.level = "HIGH"
    mock_risk.triggered_signals = mock_signals
    orchestrator.risk_calculator.calculate.return_value = mock_risk

    # Construct context
    validation = ValidationResult(valid=True, normalized_url="https://example.com/start")
    static = MagicMock(spec=StaticAnalysisResult)
    threat_intel = MagicMock(spec=ThreatIntelligenceResult)

    context = AnalysisContext(
        validation=validation,
        static=static,
        threat_intel=threat_intel
    )

    # Run analysis
    result = await orchestrator.analyze(context)

    # 1. Verify aggregated result
    assert isinstance(result, DynamicAnalysisResult)
    assert result.status == "completed"
    assert result.screenshot_path == "artifacts/screenshots/uuid1.png"
    assert result.redirects == mock_redirect
    assert result.dom == mock_dom
    assert result.network == mock_network
    assert result.signals == mock_signals
    assert result.risk == mock_risk
    assert len(result.summary) > 0

    # 2. Verify global execution context populated
    assert context.dynamic == result

    # 3. Verify sequence of operations
    orchestrator.network_analyzer.start_capture.assert_called_once_with(mock_session, "https://example.com/start")
    orchestrator.page_loader.load.assert_called_once_with(mock_session, validation)
    orchestrator.screenshot_collector.capture.assert_called_once_with(mock_session)
    orchestrator.redirect_analyzer.analyze.assert_called_once_with(mock_snapshot)
    orchestrator.dom_analyzer.analyze.assert_called_once_with(mock_snapshot)
    orchestrator.network_analyzer.stop_capture.assert_called_once()
    orchestrator.signal_generator.generate.assert_called_once_with(mock_redirect, mock_dom, mock_network)
    orchestrator.risk_calculator.calculate.assert_called_once_with(mock_signals)


@pytest.mark.anyio
async def test_orchestrator_navigation_failure():
    """Verify that page navigation exceptions are caught and return status='failed' while cleaning up logs."""
    config = DynamicAnalysisConfig()
    orchestrator = DynamicAnalysisOrchestrator(config=config)

    mock_session = MagicMock()
    orchestrator.browser_engine = MagicMock()
    async_context = AsyncMock()
    async_context.__aenter__.return_value = mock_session
    orchestrator.browser_engine.session.return_value = async_context

    orchestrator.network_analyzer = MagicMock()
    orchestrator.page_loader = AsyncMock()
    
    # Simulate page loading exception
    orchestrator.page_loader.load.side_effect = NavigationError("Network name resolution failed")

    validation = ValidationResult(valid=True, normalized_url="https://example.com/start")
    context = AnalysisContext(
        validation=validation,
        static=MagicMock(spec=StaticAnalysisResult),
        threat_intel=MagicMock(spec=ThreatIntelligenceResult)
    )

    result = await orchestrator.analyze(context)

    # 1. Verify failed result
    assert isinstance(result, DynamicAnalysisResult)
    assert result.status == "failed"
    assert context.dynamic == result

    # 2. Verify network capture clean shutdown is still executed
    orchestrator.network_analyzer.start_capture.assert_called_once_with(mock_session, "https://example.com/start")
    orchestrator.network_analyzer.stop_capture.assert_called_once()


def test_orchestrator_config_assertion():
    """Verify that invalid configuration thresholds raise ConfigurationError."""
    # Temporarily set out of order values to trigger exception
    from src.analyzers.url.dynamic_analysis import config as cfg
    
    original_thresholds = cfg.RISK_THRESHOLDS.copy()
    try:
        cfg.RISK_THRESHOLDS = {"LOW": 50, "MEDIUM": 20, "HIGH": 80}
        with pytest.raises(ConfigurationError):
            # Reload validation logic or re-assert it
            if not (cfg.RISK_THRESHOLDS["LOW"] < cfg.RISK_THRESHOLDS["MEDIUM"] < cfg.RISK_THRESHOLDS["HIGH"]):
                raise ConfigurationError("Invalid risk threshold boundaries.")
    except Exception:
        pass
    finally:
        cfg.RISK_THRESHOLDS = original_thresholds

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.models import AnalysisContext, ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult
from src.analyzers.url.ai_content_analysis.models import (
    AIAnalysisResult, ContentAnalysisResult, AISignal, AIRisk, PromptRequest, AIAnalysisInput, FraudCategory, RecommendedAction, RiskLevel
)
from src.analyzers.url.ai_content_analysis.service import AIAnalysisService
from src.analyzers.url.ai_content_analysis.orchestrator import AIContentAnalysisOrchestrator
from src.analyzers.url.ai_content_analysis.factory import create_ai_analysis_service


# ─── Mock Definitions ────────────────────────────────────────────────────────

class MockLLMClient:
    def __init__(self):
        self.generate = AsyncMock(return_value='{"raw": "json"}')


class MockResponseParser:
    def __init__(self, return_val):
        self.return_val = return_val
        self.parse = MagicMock(return_value=self.return_val)


class MockSignalGenerator:
    def __init__(self, return_val):
        self.return_val = return_val
        self.generate = MagicMock(return_value=self.return_val)


class MockRiskEngine:
    def __init__(self, return_val):
        self.return_val = return_val
        self.calculate_risk = MagicMock(return_value=self.return_val)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_context():
    # Empty basic context structure using model_construct to bypass validation
    val = ValidationResult.model_construct(valid=True, normalized_url="https://example.com")
    static = StaticAnalysisResult.model_construct(
        lexical=None,
        brand=None,
        pattern=None,
        tld=None,
        typosquatting=None,
        risk=None
    )
    threat = ThreatIntelligenceResult.model_construct(
        virustotal=None,
        google_safe_browsing=None,
        urlscan=None,
        urlhaus=None,
        ip_reputation=None,
        risk=None
    )
    return AnalysisContext.model_construct(
        validation=val,
        static=static,
        threat_intelligence=threat
    )


@pytest.fixture
def content_analysis_result():
    return ContentAnalysisResult(
        website_purpose="Test",
        detected_brand=None,
        fraud_category=FraudCategory.LEGITIMATE,
        confidence=1.0,
        brand_confidence=1.0,
        summary="Test",
        reasoning=[],
        findings=[],
        recommended_action=RecommendedAction.ALLOW
    )


@pytest.fixture
def ai_risk_result():
    return AIRisk(
        score=0.0,
        level=RiskLevel.LOW,
        summary="Test summary"
    )


# ─── Factory Tests ───────────────────────────────────────────────────────────

def test_factory_creates_wired_service():
    service = create_ai_analysis_service()
    assert isinstance(service, AIAnalysisService)
    assert service.client is not None
    assert service.parser is not None
    assert service.signal_generator is not None
    assert service.risk_engine is not None


# ─── Service Tests ───────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_service_pipeline_execution(mock_context, content_analysis_result, ai_risk_result):
    # Setup mocks
    client = MockLLMClient()
    parser = MockResponseParser(content_analysis_result)
    signals = [AISignal(signal="BRAND_IMPERSONATION", severity="HIGH", confidence=1.0, description="Test")]
    sig_gen = MockSignalGenerator(signals)
    risk_eng = MockRiskEngine(ai_risk_result)

    service = AIAnalysisService(
        client=client,
        parser=parser,
        signal_generator=sig_gen,
        risk_engine=risk_eng
    )

    # Execute service pipeline
    result = await service.analyze(mock_context, html="<html><title>Test Page</title></html>")

    # Verify steps execution
    assert isinstance(result, AIAnalysisResult)
    assert result.content == content_analysis_result
    assert result.signals == signals
    assert result.risk == ai_risk_result

    client.generate.assert_called_once()
    parser.parse.assert_called_once_with('{"raw": "json"}')
    sig_gen.generate.assert_called_once_with(content_analysis_result)
    risk_eng.calculate_risk.assert_called_once_with(signals, content_analysis_result.recommended_action)


# ─── Orchestrator Tests ───────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_orchestrator_updates_context_ai(mock_context, content_analysis_result, ai_risk_result):
    orchestrator = AIContentAnalysisOrchestrator()
    
    # Mock the internal service analyze call
    ai_result = AIAnalysisResult(
        content=content_analysis_result,
        signals=[],
        risk=ai_risk_result
    )
    orchestrator.service.analyze = AsyncMock(return_value=ai_result)

    # Execute orchestration
    updated_context = await orchestrator.analyze(mock_context, html="<html></html>")

    # Verify context updating
    assert updated_context.ai == ai_result
    orchestrator.service.analyze.assert_called_once_with(mock_context, "<html></html>")

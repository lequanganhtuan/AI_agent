import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.models import (
    AnalysisContext, ValidationResult, StaticAnalysisResult,
    ThreatIntelligenceResult, DynamicAnalysisResult
)
from src.analyzers.url.ai_content_analysis.models import (
    AIAnalysisResult, ContentAnalysisResult, AISignal, AIRisk,
    PromptRequest, AIAnalysisInput, FraudCategory, RecommendedAction, RiskLevel
)
from src.analyzers.url.ai_content_analysis.exceptions import (
    LLMResponseParseError, LLMConnectionError
)
from src.analyzers.url.ai_content_analysis.orchestrator import AIContentAnalysisOrchestrator


# ─── Mock Responses ──────────────────────────────────────────────────────────

VALID_LLM_RESPONSE = """
{
    "website_purpose": "Fake bank portal",
    "is_phishing": true,
    "fraud_category": "PHISHING",
    "detected_brand": "Chase",
    "brand_confidence": 0.95,
    "reasoning": ["Spoofed Chase banking portal logo"],
    "summary": "Phishing impersonating Chase",
    "recommended_action": "BLOCK",
    "risk_level": "CRITICAL",
    "findings": ["Fake credit card login form"]
}
"""

INVALID_SCHEMA_RESPONSE = """
{
    "website_purpose": "Incomplete schema without reasoning/findings"
}
"""


# ─── Setup Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def base_context():
    val = ValidationResult.model_construct(valid=True, normalized_url="https://example.com")
    static = StaticAnalysisResult.model_construct(
        lexical=None, brand=None, pattern=None, tld=None, typosquatting=None, risk=None
    )
    threat = ThreatIntelligenceResult.model_construct(
        virustotal=None, google_safe_browsing=None, urlscan=None, urlhaus=None, ip_reputation=None, risk=None
    )
    dynamic = DynamicAnalysisResult.model_construct(
        status="completed", screenshot_path="/mock/path.png"
    )
    return AnalysisContext.model_construct(
        validation=val,
        static=static,
        threat_intelligence=threat,
        dynamic=dynamic
    )


# ─── Integration Tests ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_check_1_happy_path_end_to_end(base_context):
    """Check 1: Happy Path End-to-End. Output is populated, context.ai is successfully assigned."""
    orchestrator = AIContentAnalysisOrchestrator()
    
    # Mock client generate method
    orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

    # Execute
    res_context = await orchestrator.analyze(base_context, html="<html></html>")

    # Verification
    assert res_context.ai is not None
    assert isinstance(res_context.ai, AIAnalysisResult)
    assert res_context.ai.content.website_purpose == "Fake bank portal"
    assert res_context.ai.content.detected_brand == "Chase"
    assert len(res_context.ai.signals) > 0
    assert res_context.ai.risk.level == RiskLevel.CRITICAL


@pytest.mark.anyio
async def test_check_2_invalid_json(base_context):
    """Check 2: Parser raises LLMResponseParseError if client returns non-JSON."""
    orchestrator = AIContentAnalysisOrchestrator()
    orchestrator.service.client.generate = AsyncMock(return_value="Hello, this is not JSON.")

    with pytest.raises(LLMResponseParseError, match="JSON structure"):
        await orchestrator.analyze(base_context, html="<html></html>")


@pytest.mark.anyio
async def test_check_3_invalid_schema(base_context):
    """Check 3: Parser raises LLMResponseParseError on incomplete schema structure."""
    orchestrator = AIContentAnalysisOrchestrator()
    orchestrator.service.client.generate = AsyncMock(return_value=INVALID_SCHEMA_RESPONSE)

    with pytest.raises(LLMResponseParseError, match="strict contract schema of LLMOutput"):
        await orchestrator.analyze(base_context, html="<html></html>")


@pytest.mark.anyio
async def test_check_4_retry_logic(base_context):
    """Check 4: Client retries twice on transient errors and succeeds on third."""
    orchestrator = AIContentAnalysisOrchestrator()
    
    # Mock _generate_once to raise transient error twice, then return valid JSON
    mock_generate = AsyncMock()
    mock_generate.side_effect = [
        LLMConnectionError("Transient 429 Rate Limit"),
        LLMConnectionError("Transient 429 Rate Limit"),
        VALID_LLM_RESPONSE
    ]
    orchestrator.service.client._generate_once = mock_generate

    # Execute
    res_context = await orchestrator.analyze(base_context, html="<html></html>")

    # Verification
    assert res_context.ai is not None
    assert mock_generate.call_count == 3


@pytest.mark.anyio
async def test_check_5_fatal_error(base_context):
    """Check 5: Fatal error is thrown immediately without retry."""
    orchestrator = AIContentAnalysisOrchestrator()
    
    # Mock _generate_once to raise a fatal validation error
    mock_generate = AsyncMock()
    # We raise validation or connection errors (non-retryable errors are fatal, e.g. 401 unauthorized)
    # The client does not retry fatal errors like 401. Let's verify by patching config or response code status
    mock_generate.side_effect = ValueError("Fatal 401 Unauthorized Credentials")
    orchestrator.service.client._generate_once = mock_generate

    with pytest.raises(ValueError, match="Fatal 401"):
        await orchestrator.analyze(base_context, html="<html></html>")

    assert mock_generate.call_count == 1


@pytest.mark.anyio
async def test_check_6_no_screenshot_execution(base_context):
    """Check 6: When vision_enabled is False, analysis still runs as text-only."""
    orchestrator = AIContentAnalysisOrchestrator()
    
    # Mock dynamic context to contain no screenshot
    base_context.dynamic.screenshot_path = None
    
    mock_generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
    orchestrator.service.client.generate = mock_generate

    res_context = await orchestrator.analyze(base_context, html="<html></html>")

    assert res_context.ai is not None
    # Verify vision_enabled parameter sent to client
    called_request = mock_generate.call_args[0][0]
    assert isinstance(called_request, PromptRequest)
    assert called_request.vision_enabled is False
    assert called_request.screenshot_base64 is None


@pytest.mark.anyio
async def test_check_7_screenshot_execution(base_context):
    """Check 7: When vision_enabled is True, client receives the image payload."""
    orchestrator = AIContentAnalysisOrchestrator()
    
    mock_generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
    orchestrator.service.client.generate = mock_generate

    # Mock screenshot encoding function
    with patch("src.analyzers.url.ai_content_analysis.input.context_builder.encode_screenshot", return_value="iVBORw0KGgo="):
        res_context = await orchestrator.analyze(base_context, html="<html></html>")

    assert res_context.ai is not None
    called_request = mock_generate.call_args[0][0]
    assert isinstance(called_request, PromptRequest)
    assert called_request.vision_enabled is True
    assert called_request.screenshot_base64 == "iVBORw0KGgo="


@pytest.mark.anyio
async def test_check_8_empty_html(base_context):
    """Check 8: When html=None, pipeline still runs normally."""
    orchestrator = AIContentAnalysisOrchestrator()
    orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

    # HTML is None, should execute cleanly without title parsing crashes
    res_context = await orchestrator.analyze(base_context, html=None)
    assert res_context.ai is not None


@pytest.mark.anyio
async def test_check_9_empty_dynamic_analysis(base_context):
    """Check 9: When context.dynamic=None, pipeline does not crash."""
    orchestrator = AIContentAnalysisOrchestrator()
    orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

    # Empty dynamic
    base_context.dynamic = None

    res_context = await orchestrator.analyze(base_context, html="<html></html>")
    assert res_context.ai is not None


@pytest.mark.anyio
async def test_check_10_empty_threat_intel(base_context):
    """Check 10: When context.threat_intelligence=None, pipeline does not crash."""
    orchestrator = AIContentAnalysisOrchestrator()
    orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

    # Empty threat
    base_context.threat_intelligence = None

    res_context = await orchestrator.analyze(base_context, html="<html></html>")
    assert res_context.ai is not None

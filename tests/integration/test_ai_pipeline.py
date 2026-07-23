import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
os.environ["SKIP_LLM_DEV"] = "true"

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


VALID_LLM_RESPONSE = """
{
    "website_purpose": "Fake bank portal",
    "is_phishing": true,
    "fraud_category": "PHISHING",
    "detected_brand": "Chase",
    "brand_confidence": 0.95,
    "verdict_confidence": 0.95,
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

def build_base_context():
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


class TestAIPipeline(unittest.IsolatedAsyncioTestCase):

    async def test_check_1_happy_path_end_to_end(self):
        """Check 1: Happy Path End-to-End. Output is populated, context.ai is successfully assigned."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

        res_context = await orchestrator.analyze(base_context, html="<html></html>")

        self.assertIsNotNone(res_context.ai)
        self.setIsInstance = isinstance(res_context.ai, AIAnalysisResult)
        self.assertTrue(self.setIsInstance)
        self.assertEqual(res_context.ai.content.website_purpose, "Fake bank portal")
        self.assertEqual(res_context.ai.content.detected_brand, "Chase")
        self.assertGreater(len(res_context.ai.signals), 0)
        self.assertEqual(res_context.ai.risk.level, RiskLevel.CRITICAL)

    async def test_check_2_invalid_json(self):
        """Check 2: Parser stores LLMResponseParseError in context.ai.error if client returns non-JSON."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value="Hello, this is not JSON.")

        res_context = await orchestrator.analyze(base_context, html="<html></html>")
        self.assertIsNotNone(res_context.ai)
        self.assertIn("Failed to parse raw text response into JSON structure", res_context.ai.error)
        self.assertIsNotNone(res_context.ai.system_prompt)
        self.assertIsNotNone(res_context.ai.user_prompt)

    async def test_check_3_invalid_schema(self):
        """Check 3: Parser stores LLMResponseParseError in context.ai.error on incomplete schema structure."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value=INVALID_SCHEMA_RESPONSE)

        res_context = await orchestrator.analyze(base_context, html="<html></html>")
        self.assertIsNotNone(res_context.ai)
        self.assertIn("JSON payload does not align with the strict contract schema of LLMOutput", res_context.ai.error)
        self.assertIsNotNone(res_context.ai.system_prompt)
        self.assertIsNotNone(res_context.ai.user_prompt)

    async def test_check_4_retry_logic(self):
        """Check 4: Client retries twice on transient errors and succeeds on third."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        
        mock_generate = AsyncMock()
        mock_generate.side_effect = [
            LLMConnectionError("Transient 429 Rate Limit"),
            LLMConnectionError("Transient 429 Rate Limit"),
            VALID_LLM_RESPONSE
        ]
        orchestrator.service.client._generate_once = mock_generate

        res_context = await orchestrator.analyze(base_context, html="<html></html>")

        self.assertIsNotNone(res_context.ai)
        self.assertIsNone(res_context.ai.error)
        self.assertEqual(mock_generate.call_count, 3)

    async def test_check_5_fatal_error(self):
        """Check 5: Fatal error is logged and stored in context.ai.error immediately without retry."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        
        mock_generate = AsyncMock()
        mock_generate.side_effect = ValueError("Fatal 401 Unauthorized Credentials")
        orchestrator.service.client._generate_once = mock_generate

        res_context = await orchestrator.analyze(base_context, html="<html></html>")
        self.assertIsNotNone(res_context.ai)
        self.assertIn("Fatal 401", res_context.ai.error)
        self.assertIsNotNone(res_context.ai.system_prompt)
        self.assertIsNotNone(res_context.ai.user_prompt)
        self.assertEqual(mock_generate.call_count, 1)

    async def test_check_6_no_screenshot_execution(self):
        """Check 6: When vision_enabled is False, analysis still runs as text-only."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        base_context.dynamic.screenshot_path = None
        
        mock_generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
        orchestrator.service.client.generate = mock_generate

        res_context = await orchestrator.analyze(base_context, html="<html></html>")

        self.assertIsNotNone(res_context.ai)
        called_request = mock_generate.call_args[0][0]
        self.assertIsInstance(called_request, PromptRequest)
        self.assertFalse(called_request.vision_enabled)
        self.assertIsNone(called_request.screenshot_base64)

    async def test_check_7_screenshot_execution(self):
        """Check 7: When vision_enabled is True, client receives the image payload."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        
        mock_generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
        orchestrator.service.client.generate = mock_generate

        with patch("src.analyzers.url.ai_content_analysis.input.context_builder.encode_screenshot", return_value="iVBORw0KGgo="):
            res_context = await orchestrator.analyze(base_context, html="<html></html>")

        self.assertIsNotNone(res_context.ai)
        called_request = mock_generate.call_args[0][0]
        self.assertIsInstance(called_request, PromptRequest)
        self.assertTrue(called_request.vision_enabled)
        self.assertEqual(called_request.screenshot_base64, "iVBORw0KGgo=")

    async def test_check_8_empty_html(self):
        """Check 8: When html=None, pipeline still runs normally."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)

        res_context = await orchestrator.analyze(base_context, html=None)
        self.assertIsNotNone(res_context.ai)

    async def test_check_9_empty_dynamic_analysis(self):
        """Check 9: When context.dynamic=None, pipeline does not crash."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
        base_context.dynamic = None

        res_context = await orchestrator.analyze(base_context, html="<html></html>")
        self.assertIsNotNone(res_context.ai)

    async def test_check_10_empty_threat_intel(self):
        """Check 10: When context.threat_intelligence=None, pipeline does not crash."""
        base_context = build_base_context()
        orchestrator = AIContentAnalysisOrchestrator()
        orchestrator.service.client.generate = AsyncMock(return_value=VALID_LLM_RESPONSE)
        base_context.threat_intelligence = None

        res_context = await orchestrator.analyze(base_context, html="<html></html>")
        self.assertIsNotNone(res_context.ai)

if __name__ == "__main__":
    unittest.main()

from __future__ import annotations
import os
import unittest
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
os.environ["SKIP_LLM_DEV"] = "true"

from src.core.models import (
    AnalysisContext,
    ValidationResult,
    StaticAnalysisResult,
    StaticRiskAnalysis,
    ThreatIntelligenceResult,
    ThreatIntelligenceRisk,
    LexicalFeatures,
    BrandAnalysis,
    PatternAnalysis,
    TLDAnalysis,
    TyposquattingAnalysis,
    VirusTotalAnalysis,
    GoogleSafeBrowsingAnalysis,
    URLScanAnalysis,
    URLHausAnalysis,
    AbuseIPDBAnalysis
)
from src.analyzers.url.dynamic_analysis.orchestrator import DynamicAnalysisOrchestrator
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType

def get_dummy_static_result(url_len: int) -> StaticAnalysisResult:
    return StaticAnalysisResult(
        lexical=LexicalFeatures(
            url_length=url_len,
            root_domain_length=19,
            full_domain_length=23,
            subdomain_count=0,
            url_special_char_count=0,
            digit_ratio_domain=0.0,
            domain_entropy=3.0,
            hyphen_count=0,
            url_depth=0,
            query_parameter_count=0,
            max_path_segment_length=0,
            longest_token_length=0,
            consecutive_digit_count=0
        ),
        brand=BrandAnalysis(),
        pattern=PatternAnalysis(),
        tld=TLDAnalysis(),
        typosquatting=TyposquattingAnalysis(),
        risk=StaticRiskAnalysis(score=0, risk_level="LOW", summary=[])
    )

def get_dummy_threat_intel() -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        virustotal=VirusTotalAnalysis(),
        google_safe_browsing=GoogleSafeBrowsingAnalysis(),
        urlscan=URLScanAnalysis(),
        urlhaus=URLHausAnalysis(query_status="no_match"),
        ip_reputation=AbuseIPDBAnalysis(abuse_score=0, total_reports=0),
        risk=ThreatIntelligenceRisk(
            score=0,
            risk_level="low",
            summary="No security threats or suspicious behaviors were detected.",
            confidence=1.0
        )
    )

class TestDynamicPipeline(unittest.IsolatedAsyncioTestCase):

    async def test_dynamic_pipeline_integration_login(self):
        """Test the complete dynamic analysis pipeline against a mock local login page."""
        current_dir = Path(__file__).parent.parent.parent
        file_path = current_dir / "tests" / "data" / "login_page.html"
        self.assertTrue(file_path.exists(), f"File not found: {file_path}")
        
        file_url = file_path.absolute().as_uri()
        
        config = DynamicAnalysisConfig()
        config.SCREENSHOT_DIRECTORY = "artifacts/test_screenshots"
        orchestrator = DynamicAnalysisOrchestrator(config=config)
        
        validation = ValidationResult(valid=True, normalized_url=file_url)
        static = get_dummy_static_result(len(file_url))
        threat_intel = get_dummy_threat_intel()
        
        context = AnalysisContext(
            validation=validation,
            static=static,
            threat_intel=threat_intel
        )
        
        result = await orchestrator.analyze(context)
        
        self.assertEqual(result.status, "completed")
        self.assertIsNotNone(result.dom)
        self.assertTrue(result.dom.has_password_field)
        self.assertTrue(result.dom.has_login_form)
        
        signal_names = [sig.signal for sig in result.signals]
        self.assertIn(DynamicSignalType.PASSWORD_FIELD, signal_names)
        self.assertIn(DynamicSignalType.LOGIN_FORM, signal_names)
        
        self.assertGreaterEqual(result.risk.score, 35)
        self.assertEqual(result.risk.level, "MEDIUM")
        
        if result.screenshot_path:
            screenshot_p = Path(result.screenshot_path)
            try:
                screenshot_p.unlink()
            except Exception:
                pass

    async def test_dynamic_pipeline_integration_obfuscation(self):
        """Test the complete dynamic analysis pipeline against a mock local obfuscated script page."""
        current_dir = Path(__file__).parent.parent.parent
        file_path = current_dir / "tests" / "data" / "obfuscated.html"
        self.assertTrue(file_path.exists())
        
        file_url = file_path.absolute().as_uri()
        
        config = DynamicAnalysisConfig()
        config.SCREENSHOT_DIRECTORY = "artifacts/test_screenshots"
        orchestrator = DynamicAnalysisOrchestrator(config=config)
        
        validation = ValidationResult(valid=True, normalized_url=file_url)
        static = get_dummy_static_result(len(file_url))
        threat_intel = get_dummy_threat_intel()
        
        context = AnalysisContext(
            validation=validation,
            static=static,
            threat_intel=threat_intel
        )
        
        result = await orchestrator.analyze(context)
        
        self.assertEqual(result.status, "completed")
        self.assertIsNotNone(result.dom)
        self.assertTrue(result.dom.has_atob)
        self.assertTrue(result.dom.has_unescape)
        
        signal_names = [sig.signal for sig in result.signals]
        self.assertIn(DynamicSignalType.ATOB_USAGE, signal_names)
        self.assertIn(DynamicSignalType.UNESCAPE_USAGE, signal_names)
        
        if result.screenshot_path:
            try:
                Path(result.screenshot_path).unlink()
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()

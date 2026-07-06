import pytest
from datetime import datetime

from src.core.report.builder import ReportBuilder
from src.core.models import AnalysisContext, ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult
from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult, ContentAnalysisResult, RecommendedAction

@pytest.fixture
def sample_context():
    validation = ValidationResult.model_construct(
        valid=True,
        normalized_url="https://example.com/login",
        cache_key="TEST_KEY"
    )
    static = StaticAnalysisResult.model_construct()
    threat_intel = ThreatIntelligenceResult.model_construct()
    
    # Mock AI content result
    ai_content = ContentAnalysisResult(
        website_purpose="Fake signin page",
        detected_brand="Chase",
        fraud_category="PHISHING",
        confidence=0.9,
        verdict_confidence=0.9,
        brand_confidence=0.95,
        summary="Phishing attempt targeting Chase Bank.",
        reasoning=["Impersonates Chase Banking"],
        findings=["Harvests logins"],
        recommended_action=RecommendedAction.BLOCK
    )
    
    ai = AIAnalysisResult(
        content=ai_content,
        signals=[],
        risk=None,
        system_prompt="System Prompt Content",
        user_prompt="User Prompt Content"
    )
    
    return AnalysisContext.model_construct(
        validation=validation,
        static=static,
        threat_intel=threat_intel,
        ai=ai
    )

def test_report_builder_mapping(sample_context):
    report = ReportBuilder.build(sample_context)
    
    # ID should be generated (UUID)
    assert report.id is not None
    assert len(report.id) == 36  # UUID length
    
    # Check general mappings
    assert report.cache_key == "TEST_KEY"
    assert report.url == "https://example.com/login"
    assert report.normalized_url == "https://example.com/login"
    assert isinstance(report.scanned_at, datetime)
    
    # Verify prompts are mapped correctly
    assert report.ai is not None
    assert report.ai.system_prompt == "System Prompt Content"
    assert report.ai.user_prompt == "User Prompt Content"
    assert report.ai.content.detected_brand == "Chase"
    assert report.ai.content.recommended_action == RecommendedAction.BLOCK

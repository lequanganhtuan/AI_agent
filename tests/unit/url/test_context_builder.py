import pytest
from src.core.models import (
    AnalysisContext,
    ValidationResult,
    StaticAnalysisResult,
    StaticRiskAnalysis,
    BrandAnalysis,
    ThreatIntelligenceResult,
    ThreatIntelligenceRisk,
    DynamicAnalysisResult,
    RedirectAnalysis,
    DOMAnalysis,
    DynamicSignal
)
from src.analyzers.url.ai_content_analysis.models import AIAnalysisInput
from src.analyzers.url.ai_content_analysis.input.context_builder import build_context

@pytest.fixture
def mock_context(tmp_path):
    validation = ValidationResult(
        valid=True,
        normalized_url="http://example.com/start",
        signals=["SHORTENED_URL"]
    )
    
    brand = BrandAnalysis(typosquatting_target="targetbrand.com")
    static_risk = StaticRiskAnalysis(
        summary=["Static analysis check finished."],
        triggered_signals=["TYPOSQUATTING"]
    )
    static = StaticAnalysisResult.model_construct(brand=brand, risk=static_risk)
    
    threat_risk = ThreatIntelligenceRisk(
        summary="Threat intelligence: high abuse detected.",
        triggered_signals=["GOOGLE_BLACKLIST"]
    )
    threat_intel = ThreatIntelligenceResult.model_construct(risk=threat_risk)
    
    redirects = RedirectAnalysis(
        redirect_count=1,
        redirect_chain=["http://example.com/start", "https://example.com/final"]
    )
    dom = DOMAnalysis(has_login_form=True)
    signals = [
        DynamicSignal(
            signal="PASSWORD_FIELD",
            severity="HIGH",
            confidence=1.0,
            evidence="Evidence detail"
        )
    ]
    
    # Save a temporary screenshot file
    screenshot_file = tmp_path / "screenshot.png"
    screenshot_file.write_bytes(b"mock bytes")
    
    dynamic = DynamicAnalysisResult(
        status="completed",
        screenshot_path=str(screenshot_file),
        redirects=redirects,
        dom=dom,
        signals=signals,
        summary=["Dynamic forms detected."]
    )
    
    return AnalysisContext(
        validation=validation,
        static=static,
        threat_intel=threat_intel,
        dynamic=dynamic
    )

def test_build_context_success(mock_context):
    html = '<html><head><title>My Login Page</title></head><body>Login to our portal.</body></html>'
    result = build_context(mock_context, html=html)
    
    assert isinstance(result, AIAnalysisInput)
    assert result.url == "http://example.com/start"
    assert result.final_url == "https://example.com/final"
    assert result.page_title == "My Login Page"
    assert result.extracted_text == "My Login Page Login to our portal."
    
    # Base64 of b"mock bytes"
    import base64
    expected_screenshot = base64.b64encode(b"mock bytes").decode("utf-8")
    assert result.screenshot_path == expected_screenshot
    assert result.legitimate_domain == "targetbrand.com"
    
    assert result.static_summary == "Static analysis check finished."
    assert result.threat_summary == "Threat intelligence: high abuse detected."
    assert result.dynamic_summary == "Dynamic forms detected."
    
    # Flat unique sorted list of signals
    assert result.important_signals == ["GOOGLE_BLACKLIST", "PASSWORD_FIELD", "SHORTENED_URL", "TYPOSQUATTING"]
    
    # Metadata dictionary mapping check
    assert result.metadata["url_length"] == len("http://example.com/start")
    assert result.metadata["page_language"] == "en"
    assert result.metadata["redirect_count"] == 1
    assert result.metadata["has_login_form"] is True

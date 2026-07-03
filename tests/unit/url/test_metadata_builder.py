import pytest
from src.core.models import (
    AnalysisContext,
    ValidationResult,
    StaticAnalysisResult,
    ThreatIntelligenceResult,
    DynamicAnalysisResult,
    RedirectAnalysis,
    DOMAnalysis
)
from src.analyzers.url.ai_content_analysis.input.metadata_builder import build_metadata

@pytest.fixture
def clean_context():
    validation = ValidationResult(valid=True, normalized_url="http://test.com/login")
    static = StaticAnalysisResult.model_construct()
    threat_intel = ThreatIntelligenceResult.model_construct()
    return AnalysisContext(
        validation=validation,
        static=static,
        threat_intel=threat_intel,
        dynamic=None
    )

def test_build_metadata_minimal(clean_context):
    meta = build_metadata(clean_context)
    assert meta == {
        "url_length": len("http://test.com/login"),
        "page_language": "en",
        "redirect_count": 0,
        "has_login_form": False,
        "has_payment_form": False,
        "has_otp_form": False
    }

def test_build_metadata_with_language_extraction(clean_context):
    html_vi = '<html lang="vi-VN"><head></head><body></body></html>'
    meta = build_metadata(clean_context, html=html_vi)
    assert meta["page_language"] == "vi"

    html_en = '<html lang="EN-US"><head></head><body></body></html>'
    meta = build_metadata(clean_context, html=html_en)
    assert meta["page_language"] == "en"

    html_no_lang = '<html><head></head><body></body></html>'
    meta = build_metadata(clean_context, html=html_no_lang)
    assert meta["page_language"] == "en"

def test_build_metadata_with_dynamic_data(clean_context):
    redirects = RedirectAnalysis(redirect_count=3)
    dom = DOMAnalysis(
        has_login_form=True,
        has_otp_field=True,
        has_credit_card_field=True
    )
    
    clean_context.dynamic = DynamicAnalysisResult(
        status="completed",
        redirects=redirects,
        dom=dom
    )
    
    meta = build_metadata(clean_context)
    assert meta["redirect_count"] == 3
    assert meta["has_login_form"] is True
    assert meta["has_payment_form"] is True
    assert meta["has_otp_form"] is True

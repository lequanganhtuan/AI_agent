import pytest
from src.core.models import (
    ValidationResult,
    URLComponents,
    LexicalFeatures,
    BrandAnalysis,
    PatternAnalysis,
    TLDAnalysis,
    TyposquattingAnalysis,
    StaticRiskAnalysis,
    StaticAnalysisResult
)
from src.analyzers.url.static.static_url_analyzer import StaticURLAnalyzer


@pytest.fixture
def static_analyzer():
    return StaticURLAnalyzer()


@pytest.fixture
def mock_valid_result():
    """
    Assuming a valid ValidationResult with a normalized structure,
    using the correct URLComponents object that accurately reflects a production environment.
    """
    mock_components = URLComponents.model_construct(
        scheme="https",
        subdomain="",
        domain="example",
        tld="com",
        full_domain="example.com",
        path="/login",
        query_parameters={} 
    )
    
    return ValidationResult.model_construct(
        valid=True,
        components=mock_components
    )


def test_static_url_analyzer_successful_flow(monkeypatch, static_analyzer, mock_valid_result):
    """
    Testing the successful integrated flow, verifying the orchestration pipeline:
    Ensuring that data passes through all stages, from component analysis to risk calculation,
    without any scrambling or object position swapping.
    """
    # 1. Generate mock data for each sub-analyzer
    mock_lexical = LexicalFeatures.model_construct(url_length=25, domain_entropy=3.0)
    mock_brand = BrandAnalysis.model_construct(detected_brand=None, brand_in_subdomain=False)
    mock_pattern = PatternAnalysis.model_construct(suspicious_keyword_count=0, suspicious_keywords=[])
    mock_tld = TLDAnalysis.model_construct(tld="com", high_risk_tld=False, medium_risk_tld=False)
    mock_typo = TyposquattingAnalysis.model_construct(suspicious=False, homoglyph_detected=False)
    
    mock_risk = StaticRiskAnalysis.model_construct(
        score=15,
        risk_level="low",
        triggered_signals=[],
        summary=["URL checks out clean"]
    )

    # Capture data to test the orchestration pipeline
    captured_inputs = {}

    def fake_calculate(lexical, brand, pattern, tld, typo, validation_result=None):
        captured_inputs["lexical"] = lexical
        captured_inputs["brand"] = brand
        captured_inputs["pattern"] = pattern
        captured_inputs["tld"] = tld
        captured_inputs["typo"] = typo
        return mock_risk

    # 3. Monkeypatch configuration precisely according to system attributes
    monkeypatch.setattr(static_analyzer.lexical_analyzer, "analyze", lambda x: mock_lexical)
    monkeypatch.setattr(static_analyzer.brand_analyzer, "analyze", lambda x: mock_brand)
    monkeypatch.setattr(static_analyzer.pattern_analyzer, "analyze", lambda x: mock_pattern)
    monkeypatch.setattr(static_analyzer.tld_analyzer, "analyze", lambda x: mock_tld)
    monkeypatch.setattr(static_analyzer.typosquatting_analyzer, "analyze", lambda x: mock_typo)
    monkeypatch.setattr(static_analyzer.risk_calculator, "calculate", fake_calculate)

    # 4. Execute main orchestration function
    result = static_analyzer.analyze(mock_valid_result)

    # 5. Verify data flow (Data Flow Orchestration)
    assert captured_inputs["lexical"] is mock_lexical, "Lexical object is incorrect when passed to Calculator"
    assert captured_inputs["brand"] is mock_brand, "Brand object is incorrect when passed to Calculator"
    assert captured_inputs["pattern"] is mock_pattern, "Pattern object is incorrect when passed to Calculator"
    assert captured_inputs["tld"] is mock_tld, "TLD object is incorrect when passed to Calculator"
    assert captured_inputs["typo"] is mock_typo, "Typosquatting object is incorrect when passed to Calculator"

    # 6. Verify the final result structure
    assert isinstance(result, StaticAnalysisResult)
    assert result.risk.score == 15
    assert result.risk.risk_level == "low"


def test_static_url_analyzer_raises_value_error_on_invalid_url(static_analyzer):
    """Ensure the system stops if the validation data has the valid = False flag."""
    invalid_result = ValidationResult.model_construct(valid=False, components=None)

    with pytest.raises(ValueError, match="ValidationResult must be valid."):
        static_analyzer.analyze(invalid_result)


def test_static_url_analyzer_raises_value_error_on_missing_components(static_analyzer):
    """
    Ensure the system requires the components attribute.
    This case forces the main logic file to have a check: if not validation_result.components
    """
    invalid_result = ValidationResult.model_construct(valid=True, components=None)

    with pytest.raises(ValueError, match="ValidationResult must contain URL components."):
        static_analyzer.analyze(invalid_result)
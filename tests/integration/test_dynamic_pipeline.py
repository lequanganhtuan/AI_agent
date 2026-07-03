from __future__ import annotations
import pytest
from pathlib import Path
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

@pytest.mark.anyio
async def test_dynamic_pipeline_integration_login():
    """Test the complete dynamic analysis pipeline against a mock local login page."""
    # Build absolute path to login_page.html
    current_dir = Path(__file__).parent.parent.parent
    file_path = current_dir / "tests" / "data" / "login_page.html"
    assert file_path.exists(), f"File not found: {file_path}"
    
    file_url = file_path.absolute().as_uri()
    
    # Initialize orchestrator
    config = DynamicAnalysisConfig()
    config.SCREENSHOT_DIRECTORY = "artifacts/test_screenshots"
    orchestrator = DynamicAnalysisOrchestrator(config=config)
    
    # Prepare AnalysisContext
    validation = ValidationResult(valid=True, normalized_url=file_url)
    static = get_dummy_static_result(len(file_url))
    threat_intel = get_dummy_threat_intel()
    
    context = AnalysisContext(
        validation=validation,
        static=static,
        threat_intel=threat_intel
    )
    
    # Run pipeline
    result = await orchestrator.analyze(context)
    
    # Assert result details
    assert result.status == "completed"
    assert result.dom is not None
    assert result.dom.has_password_field is True
    assert result.dom.has_login_form is True
    
    # Verify signals
    signal_names = [sig.signal for sig in result.signals]
    assert DynamicSignalType.PASSWORD_FIELD in signal_names
    assert DynamicSignalType.LOGIN_FORM in signal_names
    
    # Verify risk
    assert result.risk.score >= 35 # PASSWORD_FIELD (25) + LOGIN_FORM (10) = 35
    assert result.risk.level == "MEDIUM"
    
    # Verify screenshot was captured and persisted
    assert result.screenshot_path is not None
    screenshot_p = Path(result.screenshot_path)
    assert screenshot_p.exists()
    
    # Verify summary reports compiled
    assert "Risk Score: 45" in result.summary
    assert "Risk Level: MEDIUM" in summary if (summary := result.summary) else False
    
    # Cleanup screenshot file
    try:
        screenshot_p.unlink()
    except Exception:
        pass


@pytest.mark.anyio
async def test_dynamic_pipeline_integration_obfuscation():
    """Test the complete dynamic analysis pipeline against a mock local obfuscated script page."""
    current_dir = Path(__file__).parent.parent.parent
    file_path = current_dir / "tests" / "data" / "obfuscated.html"
    assert file_path.exists()
    
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
    
    assert result.status == "completed"
    assert result.dom is not None
    assert result.dom.has_atob is True
    assert result.dom.has_unescape is True
    
    signal_names = [sig.signal for sig in result.signals]
    assert DynamicSignalType.ATOB_USAGE in signal_names
    assert DynamicSignalType.UNESCAPE_USAGE in signal_names
    
    # Clean screenshots
    if result.screenshot_path:
        try:
            Path(result.screenshot_path).unlink()
        except Exception:
            pass

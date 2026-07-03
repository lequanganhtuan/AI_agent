import pytest

from src.analyzers.url.ai_content_analysis.models import (
    ContentAnalysisResult, AISignal, AISignalType, Severity, FraudCategory, RecommendedAction
)
from src.analyzers.url.ai_content_analysis.signal.registry import FRAUD_CATEGORY_SIGNAL_MAP, SIGNAL_SEVERITY_MAP
from src.analyzers.url.ai_content_analysis.signal.mapper import AISignalMapper
from src.analyzers.url.ai_content_analysis.signal.generator import AISignalGenerator


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def base_legitimate_result():
    return ContentAnalysisResult(
        website_purpose="Educational blog.",
        detected_brand=None,
        fraud_category=FraudCategory.LEGITIMATE,
        confidence=0.99,
        summary="A clean informational blog post.",
        reasoning=["Informative text block"],
        findings=["Safe content only"],
        recommended_action=RecommendedAction.ALLOW
    )


@pytest.fixture
def phish_chase_result():
    return ContentAnalysisResult(
        website_purpose=" Chase login portal clone. ",
        detected_brand="Chase",
        fraud_category=FraudCategory.PHISHING,
        confidence=0.95,
        summary="Phishing site targeting Chase customers.",
        reasoning=[" Chase Bank logo detected ", " Urgent action required to verify account "],
        findings=[" Fake login page with exfiltration endpoint ", " Password inputs visible "],
        recommended_action=RecommendedAction.BLOCK
    )


# ─── Mapper Tests ────────────────────────────────────────────────────────────

class TestAISignalMapper:
    def test_map_signals_legitimate_yields_empty_list(self, base_legitimate_result):
        mapper = AISignalMapper()
        signals = mapper.map_signals(base_legitimate_result)
        # Should return an empty list when no malicious indicators exist
        assert isinstance(signals, list)
        assert len(signals) == 0

    def test_map_signals_phishing_category_mapping(self, base_legitimate_result):
        mapper = AISignalMapper()
        # Mock phishing fraud category
        base_legitimate_result.fraud_category = FraudCategory.PHISHING
        base_legitimate_result.reasoning = ["Harvesting credentials"]
        
        signals = mapper.map_signals(base_legitimate_result)
        assert len(signals) == 1
        assert signals[0].signal == AISignalType.DATA_HARVESTING
        assert signals[0].severity == Severity.HIGH
        assert signals[0].confidence == 0.99
        assert signals[0].description == "Harvesting credentials"

    def test_map_signals_brand_impersonation_mapping(self, base_legitimate_result):
        mapper = AISignalMapper()
        # Mock brand impersonation detected
        base_legitimate_result.detected_brand = "PayPal"
        base_legitimate_result.reasoning = ["Spoofing PayPal brand portal"]
        
        signals = mapper.map_signals(base_legitimate_result)
        assert len(signals) == 1
        assert signals[0].signal == AISignalType.BRAND_IMPERSONATION
        assert signals[0].severity == Severity.HIGH
        assert signals[0].description == "Spoofing PayPal brand portal"

    def test_map_signals_findings_keyword_rules(self, base_legitimate_result):
        mapper = AISignalMapper()
        base_legitimate_result.findings = [
            "Fake login page is displayed.",
            "Urgent action required warning banner.",
            "Secure trust badge counterfeit."
        ]
        
        signals = mapper.map_signals(base_legitimate_result)
        # Should detect: FAKE_LOGIN_PAGE, URGENCY_LANGUAGE, FAKE_TRUST_SIGNAL
        signal_types = {sig.signal for sig in signals}
        expected_types = {
            AISignalType.FAKE_LOGIN_PAGE,
            AISignalType.URGENCY_LANGUAGE,
            AISignalType.FAKE_TRUST_SIGNAL
        }
        assert signal_types == expected_types
        
        # Verify severity mappings loaded from registry
        for sig in signals:
            assert sig.severity == SIGNAL_SEVERITY_MAP[sig.signal]
            assert sig.confidence == 0.99

    def test_map_signals_deduplication_rule(self, phish_chase_result):
        mapper = AISignalMapper()
        signals = mapper.map_signals(phish_chase_result)
        
        # Signals triggered:
        # - PHISHING category -> DATA_HARVESTING
        # - Password findings -> DATA_HARVESTING
        # - Chase brand -> BRAND_IMPERSONATION
        # - Urgent reasoning -> URGENCY_LANGUAGE
        # - Fake login page finding -> FAKE_LOGIN_PAGE
        
        signal_types = [sig.signal for sig in signals]
        # Verify deduplication: DATA_HARVESTING must only occur once
        assert signal_types.count(AISignalType.DATA_HARVESTING) == 1
        assert len(signal_types) == len(set(signal_types))


# ─── Generator Orchestrator Tests ─────────────────────────────────────────────

class TestAISignalGenerator:
    def test_generate_orchestrator_pipeline(self, phish_chase_result):
        mapper = AISignalMapper()
        generator = AISignalGenerator(mapper=mapper)
        
        signals = generator.generate(phish_chase_result)
        assert isinstance(signals, list)
        assert len(signals) > 0
        assert all(isinstance(sig, AISignal) for sig in signals)

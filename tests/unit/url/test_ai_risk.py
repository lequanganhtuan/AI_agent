import pytest

from src.analyzers.url.ai_content_analysis.models import (
    AIRisk, AISignal, AISignalType, Severity, RiskLevel
)
from src.analyzers.url.ai_content_analysis.risk.calculator import AIRiskCalculator
from src.analyzers.url.ai_content_analysis.risk.engine import AIRiskEngine


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def calculator():
    return AIRiskCalculator()


@pytest.fixture
def engine(calculator):
    return AIRiskEngine(calculator=calculator)


# ─── Calculator Tests ────────────────────────────────────────────────────────

class TestAIRiskCalculator:
    def test_calculate_empty_signals(self, calculator):
        risk = calculator.calculate([])
        assert risk.score == 0.0
        assert risk.level == RiskLevel.LOW
        assert risk.summary == "No AI security indicators detected."

    def test_calculate_single_signal(self, calculator):
        # FAKE_LOGIN_PAGE (40) * HIGH multiplier (1.5) * confidence (0.8) = 48.0
        signal = AISignal(
            signal=AISignalType.FAKE_LOGIN_PAGE,
            severity=Severity.HIGH,
            confidence=0.8,
            description="Mock login input page"
        )
        risk = calculator.calculate([signal])
        assert risk.score == 48.0
        assert risk.level == RiskLevel.MEDIUM
        assert risk.summary == "Detected 1 AI security indicator: Fake Login Page."

    def test_calculate_multiple_signals_clamping(self, calculator):
        # Trigger multiple large signals to exceed 100
        signals = [
            AISignal(signal=AISignalType.FAKE_LOGIN_PAGE, severity=Severity.HIGH, confidence=1.0, description="Fake Login"),
            AISignal(signal=AISignalType.DATA_HARVESTING, severity=Severity.CRITICAL, confidence=1.0, description="Data Harvesting"),
            AISignal(signal=AISignalType.BRAND_IMPERSONATION, severity=Severity.CRITICAL, confidence=1.0, description="Brand Impersonation")
        ]
        # FAKE_LOGIN_PAGE: 40 * 1.5 * 1.0 = 60.0
        # DATA_HARVESTING: 45 * 2.0 * 1.0 = 90.0
        # BRAND_IMPERSONATION: 35 * 2.0 * 1.0 = 70.0
        # Total: 220.0 -> Clamped to 100.0
        risk = calculator.calculate(signals)
        assert risk.score == 100.0
        assert risk.level == RiskLevel.CRITICAL
        # Summary alphabetical sorting: "Brand Impersonation, Data Harvesting and Fake Login Page"
        assert "Brand Impersonation, Data Harvesting and Fake Login Page" in risk.summary

    def test_calculate_duplicate_signals_summary(self, calculator):
        # Pass duplicate signal types to verify summary uses unique indicator count
        signals = [
            AISignal(signal=AISignalType.BRAND_IMPERSONATION, severity=Severity.HIGH, confidence=1.0, description="Brand 1"),
            AISignal(signal=AISignalType.BRAND_IMPERSONATION, severity=Severity.LOW, confidence=1.0, description="Brand 2"),
            AISignal(signal=AISignalType.FAKE_LOGIN_PAGE, severity=Severity.MEDIUM, confidence=1.0, description="Fake Login")
        ]
        risk = calculator.calculate(signals)
        # Expected count of unique indicators is 2 (Brand Impersonation and Fake Login Page)
        assert risk.summary.startswith("Detected 2 AI security indicators")

    def test_risk_level_boundaries(self, calculator):
        # LOW (<= 25)
        sig_low = AISignal(signal=AISignalType.FAKE_TRUST_SIGNAL, severity=Severity.LOW, confidence=1.0, description="Trust Badge")
        # 15 * 1.0 * 1.0 = 15.0 -> LOW
        assert calculator.calculate([sig_low]).level == RiskLevel.LOW

        # MEDIUM (26 - 50)
        sig_med = AISignal(signal=AISignalType.BRAND_IMPERSONATION, severity=Severity.LOW, confidence=1.0, description="Brand")
        # 35 * 1.0 * 1.0 = 35.0 -> MEDIUM
        assert calculator.calculate([sig_med]).level == RiskLevel.MEDIUM

        # HIGH (51 - 75)
        sig_high = AISignal(signal=AISignalType.DATA_HARVESTING, severity=Severity.HIGH, confidence=1.0, description="Harvest")
        # 45 * 1.5 * 1.0 = 67.5 -> HIGH
        assert calculator.calculate([sig_high]).level == RiskLevel.HIGH

        # CRITICAL (76 - 100)
        sig_crit = AISignal(signal=AISignalType.DATA_HARVESTING, severity=Severity.CRITICAL, confidence=1.0, description="Harvest")
        # 45 * 2.0 * 1.0 = 90.0 -> CRITICAL
        assert calculator.calculate([sig_crit]).level == RiskLevel.CRITICAL


# ─── Engine Orchestration Tests ────────────────────────────────────────────────

class TestAIRiskEngine:
    def test_engine_delegates_to_calculator(self, engine):
        signal = AISignal(
            signal=AISignalType.URGENCY_LANGUAGE,
            severity=Severity.LOW,
            confidence=1.0,
            description="Urgency keyword"
        )
        # URGENCY_LANGUAGE (15) * LOW multiplier (1.0) * confidence (1.0) = 15.0
        risk = engine.calculate_risk([signal])
        assert isinstance(risk, AIRisk)
        assert risk.score == 15.0
        assert risk.level == RiskLevel.LOW
        assert "Urgency Language" in risk.summary

    def test_risk_score_floors_by_recommended_action(self, engine):
        from src.analyzers.url.ai_content_analysis.models import RecommendedAction
        
        # Test empty signals with BLOCK verdict should hit the floor of 70.0 (HIGH)
        risk_block = engine.calculate_risk([], RecommendedAction.BLOCK)
        assert risk_block.score == 70.0
        assert risk_block.level == RiskLevel.HIGH
        
        # Test empty signals with WARN verdict should hit the floor of 40.0 (MEDIUM)
        risk_warn = engine.calculate_risk([], RecommendedAction.WARN)
        assert risk_warn.score == 40.0
        assert risk_warn.level == RiskLevel.MEDIUM
        
        # Test empty signals with MONITOR verdict should hit the floor of 20.0 (LOW)
        risk_monitor = engine.calculate_risk([], RecommendedAction.MONITOR)
        assert risk_monitor.score == 20.0
        assert risk_monitor.level == RiskLevel.LOW
        
        # Test empty signals with ALLOW verdict should have 0.0 score (LOW)
        risk_allow = engine.calculate_risk([], RecommendedAction.ALLOW)
        assert risk_allow.score == 0.0
        assert risk_allow.level == RiskLevel.LOW

        # Test non-empty signals with ALLOW verdict should suppress score to 0.0
        signals = [
            AISignal(signal=AISignalType.FAKE_LOGIN_PAGE, severity=Severity.HIGH, confidence=1.0, description="Fake Login")
        ]
        risk_allow_with_signals = engine.calculate_risk(signals, RecommendedAction.ALLOW)
        assert risk_allow_with_signals.score == 0.0
        assert risk_allow_with_signals.level == RiskLevel.LOW

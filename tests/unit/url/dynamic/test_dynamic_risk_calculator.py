from __future__ import annotations
import pytest
from src.core.models import DynamicSignal, DynamicRisk
from src.analyzers.url.dynamic_analysis.config import DynamicSignalType
from src.analyzers.url.dynamic_analysis.risk.dynamic_risk_calculator import DynamicRiskCalculator
from src.analyzers.url.dynamic_analysis.risk.dynamic_summary_generator import DynamicSummaryGenerator

def test_calculator_empty_signals():
    """Verify empty signal list yields score=0 and level='LOW'."""
    result = DynamicRiskCalculator.calculate([])
    assert isinstance(result, DynamicRisk)
    assert result.score == 0
    assert result.level == "LOW"
    assert result.triggered_signals == []


def test_calculator_single_low_weight():
    """Verify single low-weight signal yields correct score and 'LOW' level."""
    sig = DynamicSignal(
        signal=DynamicSignalType.ATOB_USAGE,
        severity="LOW",
        confidence=1.0,
        evidence="Detected atob() obfuscation usage in scripts."
    )
    result = DynamicRiskCalculator.calculate([sig])
    assert result.score == 5
    assert result.level == "LOW"
    assert result.triggered_signals == [sig]


def test_calculator_compounds_to_medium():
    """Verify multiple low-to-medium signals compound correctly to hit 'MEDIUM' (>= 30)."""
    # 20 (MULTI_REDIRECT) + 10 (LOGIN_FORM) = 30 -> MEDIUM
    sig1 = DynamicSignal(
        signal=DynamicSignalType.MULTI_REDIRECT,
        severity="MEDIUM",
        confidence=1.0,
        evidence="Detected 4 redirects."
    )
    sig2 = DynamicSignal(
        signal=DynamicSignalType.LOGIN_FORM,
        severity="MEDIUM",
        confidence=1.0,
        evidence="Detected login form."
    )
    result = DynamicRiskCalculator.calculate([sig1, sig2])
    assert result.score == 30
    assert result.level == "MEDIUM"
    assert result.triggered_signals == [sig1, sig2]


def test_calculator_reaches_high():
    """Verify high-risk dangerous signals accumulate quickly to reach 'HIGH' (>= 60)."""
    # 40 (REDIRECT_LOOP) + 25 (PASSWORD_FIELD) = 65 -> HIGH
    sig1 = DynamicSignal(
        signal=DynamicSignalType.REDIRECT_LOOP,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected circular redirect loop."
    )
    sig2 = DynamicSignal(
        signal=DynamicSignalType.PASSWORD_FIELD,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected password input field."
    )
    result = DynamicRiskCalculator.calculate([sig1, sig2])
    assert result.score == 65
    assert result.level == "HIGH"


def test_calculator_score_clamping():
    """Verify score totals exceeding 100 are clamped back down to 100."""
    # 40 (REDIRECT_LOOP) + 40 (PRIVATE_IP_REDIRECT) + 35 (CREDIT_CARD_FIELD) = 115 -> clamped to 100
    sig1 = DynamicSignal(
        signal=DynamicSignalType.REDIRECT_LOOP,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected circular redirect loop."
    )
    sig2 = DynamicSignal(
        signal=DynamicSignalType.PRIVATE_IP_REDIRECT,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected redirect to private IP."
    )
    sig3 = DynamicSignal(
        signal=DynamicSignalType.CREDIT_CARD_FIELD,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected credit card input field."
    )
    result = DynamicRiskCalculator.calculate([sig1, sig2, sig3])
    assert result.score == 100
    assert result.level == "HIGH"


def test_calculator_unmapped_signal():
    """Verify unmapped or unknown signals are ignored safely (treated as 0 weight)."""
    sig = DynamicSignal(
        signal="UNKNOWN_DYNAMIC_SIGNAL_XYZ",
        severity="LOW",
        confidence=1.0,
        evidence="Some unknown signal evidence."
    )
    result = DynamicRiskCalculator.calculate([sig])
    assert result.score == 0
    assert result.level == "LOW"


def test_summary_generator_output():
    """Verify DynamicSummaryGenerator constructs formatted bullet-pointed string reports."""
    sig1 = DynamicSignal(
        signal=DynamicSignalType.PASSWORD_FIELD,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected password input field."
    )
    sig2 = DynamicSignal(
        signal=DynamicSignalType.PRIVATE_IP_REDIRECT,
        severity="HIGH",
        confidence=1.0,
        evidence="Detected redirect to private IP."
    )
    risk = DynamicRisk(
        score=65,
        level="HIGH",
        triggered_signals=[sig1, sig2]
    )
    summary = DynamicSummaryGenerator.generate(risk)

    assert summary == [
        "Risk Score: 65",
        "Risk Level: HIGH",
        "Reasons:",
        "  - Detected password input field.",
        "  - Detected redirect to private IP."
    ]

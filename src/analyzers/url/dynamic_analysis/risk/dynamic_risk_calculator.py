from __future__ import annotations
from src.core.models import DynamicSignal, DynamicRisk
from src.analyzers.url.dynamic_analysis.config import DYNAMIC_SIGNAL_WEIGHTS, RISK_THRESHOLDS

class DynamicRiskCalculator:
    """Calculator for aggregating dynamic signals into composite risk scores and levels."""

    @staticmethod
    def calculate(signals: list[DynamicSignal]) -> DynamicRisk:
        """
        Calculate threat score and level based on triggered dynamic signals.
        """
        score = 0
        triggered_signals: list[DynamicSignal] = []

        for sig in signals:
            weight = DYNAMIC_SIGNAL_WEIGHTS.get(sig.signal, 0)
            score += weight
            triggered_signals.append(sig)

        # Clamp composite score to [0, 100]
        score = max(0, min(score, 100))

        # Determine level based on thresholds
        if score >= RISK_THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        return DynamicRisk(
            score=score,
            level=level,
            triggered_signals=triggered_signals
        )

from __future__ import annotations
from src.core.models import DynamicSignal, DynamicRisk
from src.analyzers.url.dynamic_analysis.config import DYNAMIC_SIGNAL_WEIGHTS, RISK_THRESHOLDS

class DynamicRiskCalculator:
    """Calculator for aggregating dynamic signals into composite risk scores and levels."""

    @staticmethod
    def calculate(signals: list[DynamicSignal], is_trusted: bool = False) -> DynamicRisk:
        """
        Calculate threat score and level based on triggered dynamic signals.
        """
        score = 0
        triggered_signals: list[DynamicSignal] = []

        # Find active signal names
        active_signals = {sig.signal for sig in signals}

        # Determine which signals to suppress because of composite signals
        suppressed_signals = set()
        
        if "LOGIN_CREDENTIAL_COLLECTION" in active_signals:
            suppressed_signals.add("LOGIN_FORM")
            suppressed_signals.add("PASSWORD_FIELD")
            
        if "LOGIN_REDIRECT_FLOW" in active_signals:
            suppressed_signals.add("PASSWORD_FIELD")
            suppressed_signals.add("META_REFRESH")
            
        if "OBFUSCATED_LOGIN_PAGE" in active_signals:
            suppressed_signals.add("PASSWORD_FIELD")
            suppressed_signals.add("EVAL_USAGE")
            suppressed_signals.add("ATOB_USAGE")
            suppressed_signals.add("UNESCAPE_USAGE")
            
        if "PAYMENT_COLLECTION" in active_signals:
            suppressed_signals.add("CREDIT_CARD_FIELD")
            suppressed_signals.add("THIRD_PARTY_DOMAIN")
            suppressed_signals.add("UNLISTED_EXTERNAL_SCRIPT")
            suppressed_signals.add("IP_ADDRESS_EXTERNAL_SCRIPT")

        # Trusted domain credential/form harvesting signals list
        trusted_suppressed = {
            "PASSWORD_FIELD",
            "LOGIN_FORM",
            "OTP_FIELD",
            "CREDIT_CARD_FIELD",
            "CCCD_FIELD",
            "LOGIN_CREDENTIAL_COLLECTION",
            "LOGIN_REDIRECT_FLOW",
            "OBFUSCATED_LOGIN_PAGE",
            "PAYMENT_COLLECTION",
            "CROSS_DOMAIN_FORM_ACTION",
            "INSECURE_FORM_ACTION",
            "GET_LOGIN_FORM",
            "EMPTY_FORM_ACTION"
        }

        for sig in signals:
            if sig.signal in suppressed_signals:
                continue

            weight = DYNAMIC_SIGNAL_WEIGHTS.get(sig.signal, 0)
            
            if is_trusted and sig.signal in trusted_suppressed:
                weight = 0
                
            score += int(weight * sig.confidence)
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

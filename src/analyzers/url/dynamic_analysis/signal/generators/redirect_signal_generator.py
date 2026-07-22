from __future__ import annotations
from src.core.models import RedirectAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType, SIGNAL_SEVERITY

class RedirectSignalGenerator:
    """Sub-generator to extract dynamic signals from RedirectAnalysis data."""

    @staticmethod
    def generate(analysis: RedirectAnalysis, config: DynamicAnalysisConfig) -> list[DynamicSignal]:
        signals = []

        # 1. Multi redirect check
        if analysis.redirect_count >= config.MULTI_REDIRECT_THRESHOLD:
            sig_type = DynamicSignalType.MULTI_REDIRECT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {analysis.redirect_count} redirects."
            ))

        # 2. Cross domain redirect
        if analysis.has_cross_domain_redirect:
            sig_type = DynamicSignalType.CROSS_DOMAIN_REDIRECT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected cross-domain redirect."
            ))

        # 3. Private IP redirect
        if analysis.redirects_to_private_ip:
            sig_type = DynamicSignalType.PRIVATE_IP_REDIRECT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected redirect to private IP."
            ))

        # 4. Raw IP redirect
        if analysis.redirects_to_ip:
            sig_type = DynamicSignalType.IP_REDIRECT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected redirect to raw IP."
            ))

        # 5. Redirect loop
        if analysis.has_redirect_loop:
            sig_type = DynamicSignalType.REDIRECT_LOOP
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected circular redirect loop."
            ))

        return signals

from __future__ import annotations
from src.core.models import DOMAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType, SIGNAL_SEVERITY

class DOMSignalGenerator:
    """Sub-generator to extract dynamic signals from DOMAnalysis data."""

    @staticmethod
    def generate(analysis: DOMAnalysis, config: DynamicAnalysisConfig) -> list[DynamicSignal]:
        signals = []

        if analysis.has_password_field:
            sig_type = DynamicSignalType.PASSWORD_FIELD
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.9,  # Upgraded to dynamic confidence
                evidence="Detected password input field."
            ))

        if analysis.has_login_form:
            sig_type = DynamicSignalType.LOGIN_FORM
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected login form."
            ))

        if analysis.has_otp_field:
            sig_type = DynamicSignalType.OTP_FIELD
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.8,  # Upgraded to dynamic confidence
                evidence="Detected One-Time Password (OTP) input field."
            ))

        if analysis.has_credit_card_field:
            sig_type = DynamicSignalType.CREDIT_CARD_FIELD
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected credit card input field."
            ))

        if analysis.has_cccd_field:
            sig_type = DynamicSignalType.CCCD_FIELD
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected CCCD/National ID input field."
            ))

        if analysis.hidden_iframe_count > 0:
            sig_type = DynamicSignalType.HIDDEN_IFRAME
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {analysis.hidden_iframe_count} hidden iframes."
            ))

        if analysis.has_meta_refresh:
            sig_type = DynamicSignalType.META_REFRESH
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected meta refresh redirect."
            ))

        if analysis.has_eval:
            sig_type = DynamicSignalType.EVAL_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.6,  # Upgraded to dynamic confidence
                evidence="Detected eval() obfuscation usage in scripts."
            ))

        if analysis.has_atob:
            sig_type = DynamicSignalType.ATOB_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected atob() obfuscation usage in scripts."
            ))

        if analysis.has_unescape:
            sig_type = DynamicSignalType.UNESCAPE_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="Detected unescape() obfuscation usage in scripts."
            ))

        if analysis.external_script_count > 0:
            sig_type = DynamicSignalType.EXTERNAL_SCRIPT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {analysis.external_script_count} external scripts."
            ))

        # Qualitative Script Analysis signals
        unlisted = getattr(analysis, "unlisted_scripts", [])
        if len(unlisted) > 0:
            sig_type = DynamicSignalType.UNLISTED_EXTERNAL_SCRIPT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.2,  # Dynamic confidence
                evidence=f"Detected external scripts loaded from unlisted/unknown domains: {', '.join(unlisted)}"
            ))

        ips = getattr(analysis, "ip_scripts", [])
        if len(ips) > 0:
            sig_type = DynamicSignalType.IP_ADDRESS_EXTERNAL_SCRIPT
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.7,
                evidence=f"Detected external scripts loaded from raw IP address: {', '.join(ips)}"
            ))

        # Deep Form Inspection signals
        if getattr(analysis, "has_cross_domain_form", False):
            sig_type = DynamicSignalType.CROSS_DOMAIN_FORM_ACTION
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.9,
                evidence=f"Cross-domain form action target detected (form exfiltration): {', '.join(analysis.form_actions)}"
            ))

        if getattr(analysis, "has_insecure_form_action", False):
            sig_type = DynamicSignalType.INSECURE_FORM_ACTION
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.8,
                evidence="Form exfiltration target uses insecure protocol (HTTP)."
            ))

        if getattr(analysis, "has_get_login_form", False):
            sig_type = DynamicSignalType.GET_LOGIN_FORM
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.8,
                evidence="Form containing credentials submitted using GET method."
            ))

        if getattr(analysis, "has_empty_action_form", False):
            sig_type = DynamicSignalType.EMPTY_FORM_ACTION
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.5,
                evidence="Form exfiltration target is empty, missing, or a relative hash (#)."
            ))

        return signals

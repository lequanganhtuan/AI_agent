from __future__ import annotations
from src.core.models import RedirectAnalysis, DOMAnalysis, NetworkAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType, SIGNAL_SEVERITY
from src.analyzers.url.dynamic_analysis.signal.generators.redirect_signal_generator import RedirectSignalGenerator
from src.analyzers.url.dynamic_analysis.signal.generators.dom_signal_generator import DOMSignalGenerator
from src.analyzers.url.dynamic_analysis.signal.generators.network_signal_generator import NetworkSignalGenerator

class DynamicSignalGenerator:
    """Orchestrator to aggregate and generate dynamic analysis signals."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    def generate(
        self,
        redirect_analysis: RedirectAnalysis,
        dom_analysis: DOMAnalysis,
        network_analysis: NetworkAnalysis
    ) -> list[DynamicSignal]:
        """
        Aggregate and return a unified list of DynamicSignals from individual analyzers.
        """
        signals = []

        # 1. Delegate to redirect sub-generator
        signals.extend(RedirectSignalGenerator.generate(redirect_analysis, self.config))

        # 2. Delegate to DOM sub-generator
        signals.extend(DOMSignalGenerator.generate(dom_analysis, self.config))

        # 3. Delegate to Network sub-generator
        signals.extend(NetworkSignalGenerator.generate(network_analysis, self.config))

        # 4. Generate Composite Signals
        active_signals = {sig.signal for sig in signals}
        
        # - LOGIN_CREDENTIAL_COLLECTION: LOGIN_FORM + PASSWORD_FIELD
        if "LOGIN_FORM" in active_signals and "PASSWORD_FIELD" in active_signals:
            sig_type = DynamicSignalType.LOGIN_CREDENTIAL_COLLECTION
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence="High-fidelity credential harvesting signature: Login form is paired with password input field."
            ))
            
        # - LOGIN_REDIRECT_FLOW: PASSWORD_FIELD + META_REFRESH
        if "PASSWORD_FIELD" in active_signals and "META_REFRESH" in active_signals:
            sig_type = DynamicSignalType.LOGIN_REDIRECT_FLOW
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.95,
                evidence="Suspicious login flow: password field page automatically redirects via meta refresh."
            ))
            
        # - OBFUSCATED_LOGIN_PAGE: PASSWORD_FIELD + (EVAL_USAGE or ATOB_USAGE or UNESCAPE_USAGE)
        obfuscations = {"EVAL_USAGE", "ATOB_USAGE", "UNESCAPE_USAGE"}
        matched_obfuscations = obfuscations.intersection(active_signals)
        if "PASSWORD_FIELD" in active_signals and len(matched_obfuscations) > 0:
            sig_type = DynamicSignalType.OBFUSCATED_LOGIN_PAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.9,
                evidence=f"Obfuscated login page: password field page uses scripting obfuscation ({', '.join(matched_obfuscations)})."
            ))
            
        # - PAYMENT_COLLECTION: CREDIT_CARD_FIELD + (THIRD_PARTY_DOMAIN or UNLISTED_EXTERNAL_SCRIPT or IP_ADDRESS_EXTERNAL_SCRIPT)
        external_risks = {"THIRD_PARTY_DOMAIN", "UNLISTED_EXTERNAL_SCRIPT", "IP_ADDRESS_EXTERNAL_SCRIPT"}
        matched_risks = external_risks.intersection(active_signals)
        if "CREDIT_CARD_FIELD" in active_signals and len(matched_risks) > 0:
            sig_type = DynamicSignalType.PAYMENT_COLLECTION
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=0.95,
                evidence=f"Payment card collection risk: credit card input field found on page running unverified external resources ({', '.join(matched_risks)})."
            ))

        return signals

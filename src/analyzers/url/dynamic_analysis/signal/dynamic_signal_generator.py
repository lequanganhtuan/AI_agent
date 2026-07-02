from __future__ import annotations
from src.core.models import RedirectAnalysis, DOMAnalysis, NetworkAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
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

        return signals

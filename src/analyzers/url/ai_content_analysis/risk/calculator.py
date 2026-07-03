from typing import List
from src.analyzers.url.ai_content_analysis.models import AIRisk, AISignal, RiskLevel
from src.analyzers.url.ai_content_analysis.risk.registry import (
    SIGNAL_WEIGHT_MAP,
    SEVERITY_MULTIPLIER,
    LOW_MAX,
    MEDIUM_MAX,
    HIGH_MAX,
)

class AIRiskCalculator:
    """Calculates the threat risk score, level, and summary from a list of generated AISignals.
    
    This calculation process is completely deterministic and independent of the LLM.
    """

    def calculate(self, signals: List[AISignal]) -> AIRisk:
        """Executes the risk calculation pipeline sequentially.
        
        Pipeline:
            _compute_score() -> _classify_level() -> _build_summary() -> AIRisk
        """
        score = self._compute_score(signals)
        level = self._classify_level(score)
        summary = self._build_summary(signals)

        return AIRisk(
            score=score,
            level=level,
            summary=summary
        )

    def _compute_score(self, signals: List[AISignal]) -> float:
        """Computes the raw composite risk score based on signal weights, multipliers, and confidence."""
        if not signals:
            return 0.0

        total_score = 0.0
        for signal in signals:
            weight = SIGNAL_WEIGHT_MAP.get(signal.signal, 0.0)
            
            # Severity mapping (coerce to uppercase to handle raw string alignment)
            severity_str = signal.severity.name if hasattr(signal.severity, "name") else str(signal.severity).upper()
            multiplier = SEVERITY_MULTIPLIER.get(severity_str, 1.0)
            
            signal_score = weight * multiplier * signal.confidence
            total_score += signal_score

        # Clamp composite score range to [0.0, 100.0]
        return max(0.0, min(total_score, 100.0))

    def _classify_level(self, score: float) -> RiskLevel:
        """Classifies the RiskLevel based on deterministic score thresholds."""
        if score <= LOW_MAX:
            return RiskLevel.LOW
        elif score <= MEDIUM_MAX:
            return RiskLevel.MEDIUM
        elif score <= HIGH_MAX:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _build_summary(self, signals: List[AISignal]) -> str:
        """Generates a deterministic summary listing detected indicator names."""
        if not signals:
            return "No AI security indicators detected."

        # Format and normalize signal type names to title case (e.g. Brand Impersonation)
        formatted_names = [
            sig.signal.value.replace("_", " ").title()
            for sig in signals
        ]
        # Sort names alphabetically to ensure absolute determinism
        unique_names = sorted(list(set(formatted_names)))

        if len(unique_names) == 1:
            return f"Detected 1 AI security indicator: {unique_names[0]}."
        
        # Combine list: "A, B and C"
        if len(unique_names) == 2:
            list_str = f"{unique_names[0]} and {unique_names[1]}"
        else:
            list_str = ", ".join(unique_names[:-1]) + f" and {unique_names[-1]}"

        return f"Detected {len(signals)} AI security indicators including {list_str}."

from typing import List, Optional
from src.analyzers.url.ai_content_analysis.models import AIRisk, AISignal, RiskLevel, RecommendedAction
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

    def calculate(self, signals: List[AISignal], recommended_action: Optional[RecommendedAction] = None) -> AIRisk:
        """Executes the risk calculation pipeline sequentially.
        
        Pipeline:
            _compute_score() -> _classify_level() -> _build_summary() -> AIRisk
        """
        score = self._compute_score(signals, recommended_action)
        level = self._classify_level(score)
        summary = self._build_summary(signals)

        return AIRisk(
            score=score,
            level=level,
            summary=summary
        )

    def _compute_score(self, signals: List[AISignal], recommended_action: Optional[RecommendedAction] = None) -> float:
        """Computes the raw composite risk score based on signal weights, multipliers, and confidence."""
        total_score = 0.0
        if signals:
            for signal in signals:
                weight = SIGNAL_WEIGHT_MAP.get(signal.signal, 0.0)
                
                # Severity mapping using Enum directly
                multiplier = SEVERITY_MULTIPLIER.get(signal.severity, 1.0)
                
                signal_score = weight * multiplier * signal.confidence
                total_score += signal_score

        # Enforce minimum risk score floors based on the recommended action
        if recommended_action:
            if recommended_action == RecommendedAction.BLOCK:
                total_score = max(total_score, 70.0)
            elif recommended_action == RecommendedAction.WARN:
                total_score = max(total_score, 40.0)
            elif recommended_action == RecommendedAction.MONITOR:
                total_score = max(total_score, 20.0)

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

        return f"Detected {len(unique_names)} AI security indicators including {list_str}."

from typing import List, Optional
from src.analyzers.url.ai_content_analysis.models import AIRisk, AISignal, RecommendedAction
from src.analyzers.url.ai_content_analysis.risk.calculator import AIRiskCalculator

class AIRiskEngine:
    """Orchestrates the AI risk calculation process.
    
    This engine holds no internal business rules and delegates computation to AIRiskCalculator.
    """

    def __init__(self, calculator: AIRiskCalculator) -> None:
        self.calculator = calculator

    def calculate_risk(self, signals: List[AISignal], recommended_action: Optional[RecommendedAction] = None) -> AIRisk:
        """Triggers the calculator execution flow and returns the deterministic AIRisk object."""
        return self.calculator.calculate(signals, recommended_action)

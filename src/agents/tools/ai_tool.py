from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.ai_content_analysis.models import (
    AIAnalysisResult, ContentAnalysisResult, AIRisk, RiskLevel, FraudCategory, RecommendedAction
)
from .base import BaseTool

class AITool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        return AIAnalysisResult(
            content=ContentAnalysisResult(
                website_purpose="Legitimate tech portal",
                detected_brand=None,
                fraud_category=FraudCategory.LEGITIMATE,
                confidence=1.0,
                brand_confidence=0.0,
                summary="Clean mock visual audit",
                reasoning=["Mock visual check passed"],
                findings=["Safe content"],
                recommended_action=RecommendedAction.ALLOW
            ),
            signals=[],
            risk=AIRisk(score=0.0, level=RiskLevel.LOW, summary="Mock AI pass"),
            system_prompt="system",
            user_prompt="user"
        )

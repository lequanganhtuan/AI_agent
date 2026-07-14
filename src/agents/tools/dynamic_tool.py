from typing import Any
from src.agents.state import URLAnalysisState
from src.core.models import DynamicAnalysisResult, DynamicRisk
from .base import BaseTool

class DynamicTool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        return DynamicAnalysisResult(
            status="completed",
            risk=DynamicRisk(score=0, level="LOW")
        )

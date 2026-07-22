from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.static.static_url_analyzer import StaticURLAnalyzer
from .base import BaseTool

class StaticTool(BaseTool):
    def __init__(self):
        self.analyzer = StaticURLAnalyzer()

    def _execute(self, state: URLAnalysisState) -> Any:
        validation_result = state.analysis.validation
        if not validation_result:
            raise ValueError("ValidationResult in state is missing")
            
        return self.analyzer.analyze(validation_result)

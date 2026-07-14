from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from .base import BaseTool

class ValidateTool(BaseTool):
    def __init__(self):
        self.analyzer = URLAnalyzer()

    def _execute(self, state: URLAnalysisState) -> Any:
        raw_url = state.analysis.raw_url
        if not raw_url:
            raise ValueError("State analysis raw_url is missing or empty")
            
        return self.analyzer.analyze(raw_url)

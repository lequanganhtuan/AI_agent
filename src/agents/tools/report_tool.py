from typing import Any
from src.agents.state import URLAnalysisState
from src.core.report.builder import ReportBuilder
from .base import BaseTool

class ReportTool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        if state.control.cache_hit and state.report:
            return state.report

        return ReportBuilder.build_from_state(state.analysis)

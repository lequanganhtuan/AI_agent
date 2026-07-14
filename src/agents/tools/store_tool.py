from typing import Any
from src.agents.state import URLAnalysisState
from .base import BaseTool

class StoreTool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        if not state.report:
            raise ValueError("No report in state to store")
        return {"stored": True}

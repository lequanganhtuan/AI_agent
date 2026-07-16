import asyncio
from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from .base import BaseTool

class ThreatTool(BaseTool):
    def __init__(self):
        self.orchestrator = ThreatIntelOrchestrator()

    def _execute(self, state: URLAnalysisState) -> Any:
        validation_result = state.analysis.validation
        if not validation_result:
            raise ValueError("ValidationResult in state is missing")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            from .base import global_executor
            future = global_executor.submit(lambda: asyncio.run(self.orchestrator.analyze_url(validation_result)))
            return future.result()
        else:
            return asyncio.run(self.orchestrator.analyze_url(validation_result))

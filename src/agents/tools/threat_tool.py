import asyncio
from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from .base import BaseTool

class ThreatTool(BaseTool):
    def __init__(self):
        pass

    def _execute(self, state: URLAnalysisState) -> Any:
        validation_result = state.analysis.validation
        if not validation_result:
            raise ValueError("ValidationResult in state is missing")

        orchestrator = ThreatIntelOrchestrator()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(orchestrator.analyze_url(validation_result)))
                return future.result()
        else:
            return asyncio.run(orchestrator.analyze_url(validation_result))

import asyncio
from typing import Any
from src.agents.state import URLAnalysisState
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from .base import BaseTool

class ThreatTool(BaseTool):
    def __init__(self):
        pass

    async def _execute(self, state: URLAnalysisState) -> Any:
        validation_result = state.analysis.validation
        if not validation_result:
            raise ValueError("ValidationResult in state is missing")

        orchestrator = ThreatIntelOrchestrator()
        return await orchestrator.analyze_url(validation_result)

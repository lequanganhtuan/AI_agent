import asyncio
from typing import Any
import logging
from src.agents.state import URLAnalysisState
from src.core.models import AnalysisContext
from src.analyzers.url.dynamic_analysis.orchestrator import DynamicAnalysisOrchestrator
from .base import BaseTool

logger = logging.getLogger(__name__)

def build_context_from_state(state: URLAnalysisState) -> AnalysisContext:
    return AnalysisContext(
        validation=state.analysis.validation,
        static=state.analysis.static,
        threat_intel=state.analysis.threat_intelligence,
        dynamic=state.analysis.dynamic,
        ai=state.analysis.ai
    )

class DynamicTool(BaseTool):
    def __init__(self):
        pass

    def _execute(self, state: URLAnalysisState) -> Any:
        context = build_context_from_state(state)
        
        orchestrator = DynamicAnalysisOrchestrator()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(orchestrator.analyze(context)))
                res = future.result()
        else:
            res = asyncio.run(orchestrator.analyze(context))
            
        return res

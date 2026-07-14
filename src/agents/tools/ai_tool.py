import asyncio
import os
import logging
from typing import Any
from src.agents.state import URLAnalysisState
from src.core.models import AnalysisContext
from src.analyzers.url.ai_content_analysis.orchestrator import AIContentAnalysisOrchestrator
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

class AITool(BaseTool):
    def __init__(self):
        self.orchestrator = AIContentAnalysisOrchestrator()

    def _execute(self, state: URLAnalysisState) -> Any:
        context = build_context_from_state(state)
        
        # Determine the key to locate cached HTML content
        cache_key = state.analysis.validation.cache_key if state.analysis.validation else None
        html = None
        
        keys_to_try = []
        if cache_key:
            keys_to_try.append(cache_key.replace(":", "_"))
        if state.execution.request_id:
            keys_to_try.append(state.execution.request_id.replace(":", "_"))
            
        for key in keys_to_try:
            html_path = f"artifacts/scans/{key}.html"
            if os.path.exists(html_path):
                try:
                    with open(html_path, "r", encoding="utf-8") as f:
                        html = f.read()
                    break
                except Exception as e:
                    logger.error(f"Failed to read dynamic HTML from cache: {str(e)}")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(self.orchestrator.analyze(context, html)))
                mutated_context = future.result()
        else:
            mutated_context = asyncio.run(self.orchestrator.analyze(context, html))
            
        return mutated_context.ai

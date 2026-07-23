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
        pass

    async def _execute(self, state: URLAnalysisState) -> Any:
        context = build_context_from_state(state)
        
        # Fast local dev mode check: bypass Gemini LLM call if SKIP_LLM_DEV is set
        if os.environ.get("SKIP_LLM_DEV", "").lower() in ("true", "1"):
            logger.info("[AITool] SKIP_LLM_DEV is enabled. Returning fast local AI result mock.")
            from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult
            return AIAnalysisResult(
                summary="Phân tích mô phỏng cho môi trường local dev (Bỏ qua Gemini LLM).",
                threat_indicators=["Mô phỏng rủi ro"],
                risk_score=75,
                confidence_score=0.9,
                analysis_details="Fast local dev mode bypass for Gemini LLM."
            )

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

        orchestrator = AIContentAnalysisOrchestrator()

        try:
            mutated_context = await orchestrator.analyze(context, html)
            return mutated_context.ai
        except Exception as err:
            logger.warning(f"[AITool] LLM Call failed ({str(err)}). Returning fallback AI analysis result.")
            from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult
            return AIAnalysisResult(
                summary="Không thể phân tích bằng Gemini (Hết quota hoặc lỗi kết nối).",
                threat_indicators=["Gemini Quota Limited"],
                risk_score=50,
                confidence_score=0.5,
                analysis_details=f"Fallback trigger: {str(err)}"
            )

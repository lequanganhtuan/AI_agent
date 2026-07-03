import logging
from typing import Optional

from src.core.models import AnalysisContext
from src.analyzers.url.ai_content_analysis.factory import create_ai_analysis_service
from src.analyzers.url.ai_content_analysis.input.context_builder import build_context
from src.analyzers.url.ai_content_analysis.prompt.builder import build_prompt
from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult

logger = logging.getLogger(__name__)

class AIContentAnalysisOrchestrator:
    """Orchestrates Phase 5 AI Content Analysis pipeline lifecycle.
    
    Acts as the outer boundary layer and is responsible for mutating the AnalysisContext.
    """

    def __init__(self) -> None:
        # Initialise service dependencies via factory to isolate model vendor swaps
        self.service = create_ai_analysis_service()

    async def analyze(self, context: AnalysisContext, html: Optional[str] = None) -> AnalysisContext:
        """Orchestrates the context analysis execution flow and stores results on context.ai."""
        try:
            result = await self.service.analyze(context, html)
            context.ai = result
        except Exception as e:
            logger.error(f"AI content analysis failed: {str(e)}", exc_info=True)
            # Try to build prompts so the copy-paste panel is still populated for testing
            system_prompt = None
            user_prompt = None
            try:
                analysis_input = build_context(context, html)
                prompt_request = build_prompt(analysis_input)
                system_prompt = prompt_request.system_prompt
                user_prompt = prompt_request.user_prompt
            except Exception as pe:
                logger.error(f"Failed to build prompts for fallback: {str(pe)}")
            
            context.ai = AIAnalysisResult(
                error=str(e),
                system_prompt=system_prompt,
                user_prompt=user_prompt
            )
        return context


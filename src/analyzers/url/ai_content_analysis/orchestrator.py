import logging
from typing import Optional

from src.core.models import AnalysisContext
from src.analyzers.url.ai_content_analysis.factory import create_ai_analysis_service

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
        result = await self.service.analyze(context, html)
        context.ai = result
        return context

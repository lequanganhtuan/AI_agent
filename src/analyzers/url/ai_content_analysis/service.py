import logging
from typing import Optional

from src.core.models import AnalysisContext
from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult
from src.analyzers.url.ai_content_analysis.input.context_builder import build_context
from src.analyzers.url.ai_content_analysis.prompt.builder import build_prompt

logger = logging.getLogger(__name__)

class AIAnalysisService:
    """Coordinates the execution of the entire AI Content Analysis pipeline.
    
    This service is stateless and expects all dependencies to be injected.
    It returns the resulting AIAnalysisResult domain model without modifying the context.
    """

    def __init__(
        self,
        client,
        parser,
        signal_generator,
        risk_engine,
    ) -> None:
        self.client = client
        self.parser = parser
        self.signal_generator = signal_generator
        self.risk_engine = risk_engine

    async def analyze(self, context: AnalysisContext, html: Optional[str] = None) -> AIAnalysisResult:
        """Executes the AI Content Analysis pipeline sequentially.
        
        Pipeline:
            build_context() -> build_prompt() -> client.generate() ->
            parser.parse() -> signal_generator.generate() ->
            risk_engine.calculate_risk() -> AIAnalysisResult
        """
        logger.info("Starting AI Content Analysis")

        # Step 1: Build input context
        analysis_input = build_context(context, html)

        # Step 2: Build prompt payload
        prompt_request = build_prompt(analysis_input)

        # Step 3: Send request to vendor client
        raw_response = await self.client.generate(prompt_request)

        # Step 4: Parse raw text response to verified model
        content_result = self.parser.parse(raw_response)

        # Step 5: Generate threat signals from analysis contents
        signals = self.signal_generator.generate(content_result)

        # Step 6: Calculate risk scores and levels from signals
        risk = self.risk_engine.calculate_risk(signals, content_result.recommended_action)

        logger.info("Completed AI Content Analysis")

        # Step 7: Assemble and return results
        return AIAnalysisResult(
            content=content_result,
            signals=signals,
            risk=risk,
            system_prompt=prompt_request.system_prompt,
            user_prompt=prompt_request.user_prompt
        )


import json
from typing import Any
from src.analyzers.url.ai_content_analysis.models import ContentAnalysisResult, LLMOutput
from src.analyzers.url.ai_content_analysis.exceptions import LLMResponseParseError

class AIResponseParser:
    """Orchestrates the conversion of a raw LLM text response into a verified domain model.
    
    This class contains zero internal validation or transformation business logic.
    """
    
    def __init__(self, validator: Any, normalizer: Any) -> None:
        self.validator = validator
        self.normalizer = normalizer

    def parse(self, raw_response: str) -> ContentAnalysisResult:
        """Executes the parsing pipeline sequentially.
        
        Pipeline:
            json.loads() -> validate() -> normalize() -> ContentAnalysisResult
            
        Args:
            raw_response: The raw string block returned by the LLM client wrapper.
            
        Returns:
            ContentAnalysisResult: The immutable, system-ready domain structure.
            
        Raises:
            LLMResponseParseError: If the raw response is not structurally sound JSON.
        """
        try:
            # Step 1: Structural string deserialization
            raw_data = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise LLMResponseParseError(
                f"Failed to parse raw text response into JSON structure: {str(exc)}"
            ) from exc

        # Step 2: Extract structural JSON object directly to an LLMOutput verification contract
        # (This leverages standard Pydantic structural data typing first)
        try:
            llm_output = LLMOutput(**raw_data)
        except Exception as exc:
            raise LLMResponseParseError(
                f"JSON payload does not align with the strict contract schema of LLMOutput: {str(exc)}"
            ) from exc

        # Step 3: Run domain business rules evaluations
        self.validator.validate(llm_output)

        # Step 4: Execute textual cleanup and instantiate the system-side domain model
        return self.normalizer.normalize(llm_output)

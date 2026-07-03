from src.analyzers.url.ai_content_analysis.models import (
    LLMOutput, 
    FraudCategory, 
    RiskLevel, 
    RecommendedAction
)
from src.analyzers.url.ai_content_analysis.exceptions import LLMResponseValidationError

class AIResponseValidator:
    """Validates domain-level logical rules and semantic data assertions for the LLM output.
    
    This component does not execute formatting adjustments or data updates; it is entirely side-effect free.
    """

    def validate(self, output: LLMOutput) -> None:
        """Enforces critical security and semantic validation constraints on the LLM output data.

        Args:
            output: The verified internal LLMOutput structure.

        Raises:
            LLMResponseValidationError: If any semantic constraint fails verification.
        """
        # 1. Structural reasoning validation
        if not output.reasoning:
            raise LLMResponseValidationError("The 'reasoning' telemetry array cannot be blank or empty.")

        # 2. Key findings array safety validation
        if output.findings is None:
            raise LLMResponseValidationError("The 'findings' collector cannot be a null value or missing.")

        # 3. Dynamic textual summary safety validation
        if not output.summary or not output.summary.strip():
            raise LLMResponseValidationError("The structural analytical 'summary' text block cannot be empty.")

        # 4. Strict numerical confidence ranges boundary checks
        if not (0.0 <= output.brand_confidence <= 1.0):
            raise LLMResponseValidationError(
                f"The brand confidence value '{output.brand_confidence}' violates required numeric boundaries [0.0, 1.0]."
            )

        # 5. Native enumeration domain verification boundaries
        # (Pydantic values conversion handles typical instantiation checks, but strict verification ensures type parity)
        if output.fraud_category not in FraudCategory:
            raise LLMResponseValidationError(f"The structural categorization token '{output.fraud_category}' is invalid.")
            
        if output.risk_level not in RiskLevel:
            raise LLMResponseValidationError(f"The calculated risk profile identifier '{output.risk_level}' is unmapped.")
            
        if output.recommended_action not in RecommendedAction:
            raise LLMResponseValidationError(f"The operational system directive '{output.recommended_action}' is invalid.")

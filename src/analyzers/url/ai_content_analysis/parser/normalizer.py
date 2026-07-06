from typing import Dict
from src.analyzers.url.ai_content_analysis.models import ContentAnalysisResult, LLMOutput, FraudCategory

class AIResponseNormalizer:
    """Transforms raw textual inputs, fixes character discrepancies, and builds the internal domain model."""

    def __init__(self) -> None:
        # Standard structural lookup table to decouple dynamic variant representations
        self._brand_normalization_map: Dict[str, str] = {
            "microsoft": "Microsoft",
            "google": "Google",
            "apple": "Apple",
            "facebook": "Facebook",
            "meta": "Meta",
            "amazon": "Amazon",
            "paypal": "PayPal",
            "netflix": "Netflix"
        }

    def normalize(self, output: LLMOutput) -> ContentAnalysisResult:
        """Sanitizes text fields and packages the cleaned data into the final ContentAnalysisResult model.

        Args:
            output: The validated raw LLMOutput context.

        Returns:
            ContentAnalysisResult: The system-side internal domain representation.
        """
        # One-shot scalar text string space normalization
        clean_summary = output.summary.strip()

        # Array list transformations - Strip space and drop empty string fragments
        clean_reasoning = [line.strip() for line in output.reasoning if line and line.strip()]
        clean_findings = [finding.strip() for finding in output.findings if finding and finding.strip()]

        # Dynamic variable mapping and casing adjustments
        raw_brand = output.detected_brand
        normalized_brand = None

        if raw_brand and raw_brand.strip():
            lookup_key = raw_brand.strip().lower()
            # Map standard variations or retain the capitalized raw format
            normalized_brand = self._brand_normalization_map.get(lookup_key, raw_brand.strip())

        # Enforce target structural domain invariance constraints
        # Rule: Legitimate websites cannot possess an associated impersonation brand tag
        if output.fraud_category == FraudCategory.LEGITIMATE:
            normalized_brand = None

        # Build and return the final target domain model
        return ContentAnalysisResult(
            website_purpose=output.website_purpose.strip(),
            detected_brand=normalized_brand,
            fraud_category=output.fraud_category,
            confidence=output.verdict_confidence,  # Map LLM's verdict_confidence directly to overall confidence
            brand_confidence=output.brand_confidence,  # Keep brand_confidence separate
            summary=clean_summary,
            reasoning=clean_reasoning,
            findings=clean_findings,
            recommended_action=output.recommended_action
        )
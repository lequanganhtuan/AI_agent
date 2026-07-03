import pytest
import json

from src.analyzers.url.ai_content_analysis.models import (
    LLMOutput, ContentAnalysisResult, FraudCategory, RiskLevel, RecommendedAction
)
from src.analyzers.url.ai_content_analysis.exceptions import (
    LLMResponseParseError, LLMResponseValidationError
)
from src.analyzers.url.ai_content_analysis.parser.parser import AIResponseParser
from src.analyzers.url.ai_content_analysis.parser.validator import AIResponseValidator
from src.analyzers.url.ai_content_analysis.parser.normalizer import AIResponseNormalizer


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_llm_output_data():
    return {
        "website_purpose": "Fake banking login portal.",
        "is_phishing": True,
        "fraud_category": "PHISHING",
        "detected_brand": "paypal",
        "brand_confidence": 0.95,
        "reasoning": [" Spoofed PayPal logo ", "  Credential exfiltration form  "],
        "summary": "  High probability phishing attempt targeting PayPal accounts.  ",
        "recommended_action": "BLOCK",
        "risk_level": "CRITICAL",
        "findings": [" Fake login inputs ", " Suspicious redirection "]
    }


@pytest.fixture
def parser_instance():
    v = AIResponseValidator()
    n = AIResponseNormalizer()
    return AIResponseParser(validator=v, normalizer=n)


# ─── Validator Tests ─────────────────────────────────────────────────────────

class TestValidator:
    def test_validate_success(self, valid_llm_output_data):
        validator = AIResponseValidator()
        output = LLMOutput(**valid_llm_output_data)
        # Should execute successfully without throwing exceptions
        validator.validate(output)

    def test_validate_empty_reasoning_fails(self, valid_llm_output_data):
        validator = AIResponseValidator()
        valid_llm_output_data["reasoning"] = []
        output = LLMOutput(**valid_llm_output_data)
        with pytest.raises(LLMResponseValidationError, match="reasoning"):
            validator.validate(output)

    def test_validate_missing_findings_fails(self, valid_llm_output_data):
        validator = AIResponseValidator()
        valid_llm_output_data["findings"] = None
        # Pydantic validation allows None if defined, but custom validate throws
        output = LLMOutput.model_construct(**valid_llm_output_data)
        with pytest.raises(LLMResponseValidationError, match="findings"):
            validator.validate(output)

    def test_validate_empty_summary_fails(self, valid_llm_output_data):
        validator = AIResponseValidator()
        valid_llm_output_data["summary"] = "   "
        output = LLMOutput(**valid_llm_output_data)
        with pytest.raises(LLMResponseValidationError, match="summary"):
            validator.validate(output)

    def test_validate_out_of_bound_confidence_fails(self, valid_llm_output_data):
        validator = AIResponseValidator()
        valid_llm_output_data["brand_confidence"] = 1.5
        # Skip Pydantic check using model_construct to test validator checks
        output = LLMOutput.model_construct(**valid_llm_output_data)
        with pytest.raises(LLMResponseValidationError, match="confidence"):
            validator.validate(output)


# ─── Normalizer Tests ───────────────────────────────────────────────────────

class TestNormalizer:
    def test_normalizer_cleans_fields(self, valid_llm_output_data):
        normalizer = AIResponseNormalizer()
        output = LLMOutput(**valid_llm_output_data)
        result = normalizer.normalize(output)
        
        assert isinstance(result, ContentAnalysisResult)
        assert result.website_purpose == "Fake banking login portal."
        assert result.detected_brand == "PayPal" # Normalized casing
        assert result.confidence == 0.95
        assert result.summary == "High probability phishing attempt targeting PayPal accounts."
        assert result.reasoning == ["Spoofed PayPal logo", "Credential exfiltration form"]

    def test_normalizer_retains_unknown_brand(self, valid_llm_output_data):
        normalizer = AIResponseNormalizer()
        valid_llm_output_data["detected_brand"] = "CustomUnknownBrand"
        output = LLMOutput(**valid_llm_output_data)
        result = normalizer.normalize(output)
        assert result.detected_brand == "CustomUnknownBrand"

    def test_normalizer_strips_brand_for_legitimate(self, valid_llm_output_data):
        normalizer = AIResponseNormalizer()
        valid_llm_output_data["fraud_category"] = "LEGITIMATE"
        valid_llm_output_data["detected_brand"] = "Google"
        output = LLMOutput(**valid_llm_output_data)
        result = normalizer.normalize(output)
        # Invariance rule: Legitimate websites cannot possess a brand impersonation tag
        assert result.detected_brand is None


# ─── Parser Orchestrator Tests ────────────────────────────────────────────────

class TestParserOrchestrator:
    def test_parse_success(self, parser_instance, valid_llm_output_data):
        raw_json_str = json.dumps(valid_llm_output_data)
        result = parser_instance.parse(raw_json_str)
        assert isinstance(result, ContentAnalysisResult)
        assert result.detected_brand == "PayPal"

    def test_parse_invalid_json_fails(self, parser_instance):
        with pytest.raises(LLMResponseParseError, match="Failed to parse raw text response"):
            parser_instance.parse("{invalid-json-string")

    def test_parse_schema_mismatch_fails(self, parser_instance, valid_llm_output_data):
        # Remove a required field
        del valid_llm_output_data["website_purpose"]
        raw_json_str = json.dumps(valid_llm_output_data)
        with pytest.raises(LLMResponseParseError, match="strict contract schema of LLMOutput"):
            parser_instance.parse(raw_json_str)

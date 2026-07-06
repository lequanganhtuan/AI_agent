import json
import pytest
from src.analyzers.url.ai_content_analysis.models import (
    AIAnalysisInput, PromptRequest, LLMOutput
)
from src.analyzers.url.ai_content_analysis.prompt.system_prompt import SYSTEM_PROMPT
from src.analyzers.url.ai_content_analysis.prompt.schema import LLM_JSON_SCHEMA
from src.analyzers.url.ai_content_analysis.prompt.user_prompt import build_user_prompt, MAX_TEXT_LENGTH
from src.analyzers.url.ai_content_analysis.prompt.builder import build_prompt


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_input():
    return AIAnalysisInput(
        url="http://example.com/login",
        final_url="https://example.com/final",
        page_title="Example Login",
        extracted_text="Please enter your credentials to continue.",
        screenshot_path="base64encodedstring",
        legitimate_domain="example.com",
        static_summary="Lexical risk detected.",
        threat_summary="VirusTotal flagged 2 engines.",
        dynamic_summary="Login form detected with credential fields.",
        important_signals=["PASSWORD_FIELD", "LOGIN_FORM", "SHORTENED_URL"],
        metadata={
            "url_length": 28,
            "page_language": "en",
            "redirect_count": 2,
            "has_login_form": True,
            "has_payment_form": False,
            "has_otp_form": False
        }
    )


@pytest.fixture
def minimal_input():
    return AIAnalysisInput(
        url="http://safe.com",
        final_url="http://safe.com",
        page_title="",
        extracted_text="",
        screenshot_path=None,
        legitimate_domain=None,
        static_summary="",
        threat_summary="",
        dynamic_summary="",
        important_signals=[],
        metadata={
            "url_length": 15,
            "page_language": "en",
            "redirect_count": 0,
            "has_login_form": False,
            "has_payment_form": False,
            "has_otp_form": False
        }
    )


# ─── system_prompt.py Tests ─────────────────────────────────────────────────

class TestSystemPrompt:
    def test_system_prompt_is_string(self):
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 500

    def test_system_prompt_defines_persona(self):
        assert "Cyber Security Expert" in SYSTEM_PROMPT
        assert "Phishing Analyst" in SYSTEM_PROMPT

    def test_system_prompt_no_chatgpt_reference(self):
        assert "ChatGPT" not in SYSTEM_PROMPT

    def test_system_prompt_json_output_guardrail(self):
        assert "JSON" in SYSTEM_PROMPT
        assert "Markdown" in SYSTEM_PROMPT

    def test_system_prompt_hallucination_mitigation(self):
        assert "NEVER speculate" in SYSTEM_PROMPT


# ─── schema.py Tests ────────────────────────────────────────────────────────

class TestSchema:
    def test_schema_is_valid_json(self):
        parsed = json.loads(LLM_JSON_SCHEMA)
        assert parsed["type"] == "object"
        assert "properties" in parsed

    def test_schema_matches_llm_output_fields(self):
        parsed = json.loads(LLM_JSON_SCHEMA)
        expected_keys = {
            "website_purpose", "is_phishing", "fraud_category",
            "detected_brand", "brand_confidence", "verdict_confidence", "reasoning",
            "summary", "recommended_action", "risk_level", "findings"
        }
        assert set(parsed["properties"].keys()) == expected_keys

    def test_schema_required_matches_properties(self):
        parsed = json.loads(LLM_JSON_SCHEMA)
        assert set(parsed["required"]) == set(parsed["properties"].keys())


# ─── user_prompt.py Tests ───────────────────────────────────────────────────

class TestUserPrompt:
    def test_user_prompt_contains_sections(self, sample_input):
        prompt = build_user_prompt(sample_input)
        assert "### TASK" in prompt
        assert "### INPUT" in prompt
        assert "### METADATA" in prompt
        assert "### SIGNALS" in prompt
        assert "### STATIC ANALYSIS" in prompt
        assert "### THREAT INTELLIGENCE" in prompt
        assert "### DYNAMIC ANALYSIS" in prompt
        assert "### VISIBLE WEBSITE CONTENT" in prompt
        assert "### EXPECTED OUTPUT" in prompt

    def test_user_prompt_renders_metadata_cleanly(self, sample_input):
        prompt = build_user_prompt(sample_input)
        assert "- URL Length: 28" in prompt
        assert "- Language: en" in prompt
        assert "- Redirect Count: 2" in prompt
        assert "- Has Login Form: True" in prompt

    def test_user_prompt_renders_signals_as_list(self, sample_input):
        prompt = build_user_prompt(sample_input)
        assert "- PASSWORD_FIELD" in prompt
        assert "- LOGIN_FORM" in prompt
        assert "- SHORTENED_URL" in prompt

    def test_user_prompt_no_raw_dict_dump(self, sample_input):
        prompt = build_user_prompt(sample_input)
        # Should not contain Python dict repr like {'url_length': 28, ...}
        assert "{'url_length'" not in prompt
        assert '{"url_length"' not in prompt

    def test_user_prompt_text_at_end(self, sample_input):
        prompt = build_user_prompt(sample_input)
        content_idx = prompt.index("### VISIBLE WEBSITE CONTENT")
        expected_idx = prompt.index("### EXPECTED OUTPUT")
        # Text section must come after all other data sections
        assert content_idx > prompt.index("### DYNAMIC ANALYSIS")
        # Expected output is the only thing after visible content
        assert expected_idx > content_idx

    def test_user_prompt_truncates_long_text(self):
        long_text = "A" * (MAX_TEXT_LENGTH + 5000)
        inp = AIAnalysisInput(
            url="http://x.com", final_url="http://x.com",
            page_title="", extracted_text=long_text,
            screenshot_path=None, legitimate_domain=None,
            static_summary="", threat_summary="", dynamic_summary="",
            important_signals=[], metadata={"url_length": 12, "page_language": "en",
            "redirect_count": 0, "has_login_form": False, "has_payment_form": False,
            "has_otp_form": False}
        )
        prompt = build_user_prompt(inp)
        assert "[...TRUNCATED]" in prompt
        # The full long_text should NOT appear
        assert long_text not in prompt

    def test_user_prompt_empty_signals(self, minimal_input):
        prompt = build_user_prompt(minimal_input)
        assert "- No signals detected." in prompt

    def test_user_prompt_empty_summaries(self, minimal_input):
        prompt = build_user_prompt(minimal_input)
        assert "No static analysis summary available." in prompt
        assert "No threat intelligence summary available." in prompt
        assert "No dynamic analysis summary available." in prompt

    def test_user_prompt_includes_legitimate_domain(self, sample_input):
        prompt = build_user_prompt(sample_input)
        assert "- Suspected Legitimate Domain: example.com" in prompt

    def test_user_prompt_omits_legitimate_domain_when_none(self, minimal_input):
        prompt = build_user_prompt(minimal_input)
        assert "Suspected Legitimate Domain" not in prompt


# ─── builder.py Tests ───────────────────────────────────────────────────────

class TestBuilder:
    def test_build_prompt_returns_prompt_request(self, sample_input):
        result = build_prompt(sample_input)
        assert isinstance(result, PromptRequest)

    def test_build_prompt_system_prompt_is_pure_constant(self, sample_input):
        result = build_prompt(sample_input)
        # System prompt must be the exact static constant — no schema appended
        assert result.system_prompt == SYSTEM_PROMPT

    def test_build_prompt_schema_in_user_prompt_not_system(self, sample_input):
        result = build_prompt(sample_input)
        # Schema keys must appear in user prompt
        assert "website_purpose" in result.user_prompt
        assert "is_phishing" in result.user_prompt
        assert "### EXPECTED OUTPUT" in result.user_prompt

    def test_build_prompt_user_prompt_has_sections(self, sample_input):
        result = build_prompt(sample_input)
        assert "### TASK" in result.user_prompt
        assert "### INPUT" in result.user_prompt

    def test_build_prompt_response_schema_is_llm_output(self, sample_input):
        result = build_prompt(sample_input)
        assert result.response_schema is LLMOutput

    def test_build_prompt_vision_enabled_with_screenshot(self, sample_input):
        result = build_prompt(sample_input)
        assert result.vision_enabled is True
        assert result.screenshot_base64 == sample_input.screenshot_path

    def test_build_prompt_vision_disabled_without_screenshot(self, minimal_input):
        result = build_prompt(minimal_input)
        assert result.vision_enabled is False
        assert result.screenshot_base64 is None



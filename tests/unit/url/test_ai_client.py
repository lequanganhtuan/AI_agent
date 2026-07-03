import pytest
import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock
from google.genai.errors import APIError

from src.analyzers.url.ai_content_analysis.models import PromptRequest, LLMOutput
from src.analyzers.url.ai_content_analysis.exceptions import (
    AIContentAnalysisError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMRateLimitError,
)
from src.analyzers.url.ai_content_analysis.client.gemini_client import GeminiClient
from src.analyzers.url.ai_content_analysis.client.retry import execute_with_retry


# ─── Retry Module Tests ──────────────────────────────────────────────────────

class TestRetry:
    @pytest.mark.anyio
    async def test_retry_success(self):
        call_count = 0
        async def mock_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await execute_with_retry(mock_func)
        assert result == "success"
        assert call_count == 1

    @pytest.mark.anyio
    async def test_retry_transient_failure_then_success(self, monkeypatch):
        # Speed up sleeps
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        
        call_count = 0
        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise LLMRateLimitError("Transient Rate Limit")
            return "success"

        result = await execute_with_retry(mock_func)
        assert result == "success"
        assert call_count == 3

    @pytest.mark.anyio
    async def test_retry_transient_exceeds_max_retries(self, monkeypatch):
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        
        async def mock_func():
            raise LLMTimeoutError("Timeout error")

        with pytest.raises(LLMTimeoutError):
            await execute_with_retry(mock_func)

    @pytest.mark.anyio
    async def test_retry_propagates_fatal_error_immediately(self, monkeypatch):
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        
        call_count = 0
        async def mock_func():
            nonlocal call_count
            call_count += 1
            raise AIContentAnalysisError("Fatal config error")

        with pytest.raises(AIContentAnalysisError):
            await execute_with_retry(mock_func)
        
        assert call_count == 1  # Should NOT retry


# ─── Gemini Client Payload Assembly & Configuration Tests ───────────────────────

class TestGeminiClientPayload:
    @pytest.mark.anyio
    async def test_generate_text_only(self):
        client = GeminiClient(api_key="test_key")
        
        # Mock generate content response
        mock_response = MagicMock()
        mock_response.text = "Analysis Result String"
        mock_response.usage_metadata = MagicMock(
            prompt_token_count=10,
            response_token_count=5,
            total_token_count=15
        )
        
        mock_generate = AsyncMock(return_value=mock_response)
        client.client.aio.models.generate_content = mock_generate
        
        req = PromptRequest(
            system_prompt="system instructions",
            user_prompt="user instructions",
            response_schema=LLMOutput,
            vision_enabled=False
        )
        
        result = await client.generate(req)
        assert result == "Analysis Result String"
        
        # Verify calls and mapping
        mock_generate.assert_called_once()
        kwargs = mock_generate.call_args[1]
        assert kwargs["contents"] == ["user instructions"]
        assert kwargs["config"].system_instruction == "system instructions"
        assert kwargs["config"].temperature == 0.0

    @pytest.mark.anyio
    async def test_generate_multimodal_vision(self):
        client = GeminiClient(api_key="test_key")
        
        mock_response = MagicMock()
        mock_response.text = "Vision Result String"
        mock_response.usage_metadata = None
        
        mock_generate = AsyncMock(return_value=mock_response)
        client.client.aio.models.generate_content = mock_generate
        
        # YmFzZTY0cGF5bG9hZA== is 'base64payload' in base64
        req = PromptRequest(
            system_prompt="system instructions",
            user_prompt="user instructions",
            response_schema=LLMOutput,
            vision_enabled=True,
            screenshot_base64="YmFzZTY0cGF5bG9hZA=="
        )

        
        result = await client.generate(req)
        assert result == "Vision Result String"
        
        # Verify multimodal contents mapping
        mock_generate.assert_called_once()
        kwargs = mock_generate.call_args[1]
        assert len(kwargs["contents"]) == 2
        assert kwargs["contents"][0] == "user instructions"
        
        # Extract binary data mapping from the part object
        part = kwargs["contents"][1]
        assert part.inline_data.data == b"base64payload"
        assert part.inline_data.mime_type == "image/png"


# ─── Gemini Client Error Handling & Translation Tests ─────────────────────────

class TestGeminiClientErrorHandling:
    @pytest.mark.anyio
    async def test_rate_limit_error_translation(self):
        client = GeminiClient(api_key="test_key")
        
        mock_generate = AsyncMock(side_effect=APIError(
            code=429,
            response_json=None,
            response=MagicMock()
        ))
        client.client.aio.models.generate_content = mock_generate
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMRateLimitError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_timeout_error_translation(self):
        client = GeminiClient(api_key="test_key")
        
        mock_generate = AsyncMock(side_effect=APIError(
            code=408,
            response_json=None,
            response=MagicMock()
        ))
        client.client.aio.models.generate_content = mock_generate
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMTimeoutError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_server_error_transient_translation(self):
        client = GeminiClient(api_key="test_key")
        
        mock_generate = AsyncMock(side_effect=APIError(
            code=503,
            response_json=None,
            response=MagicMock()
        ))
        client.client.aio.models.generate_content = mock_generate
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMConnectionError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_status_error_fatal_translation(self):
        client = GeminiClient(api_key="test_key")
        
        mock_generate = AsyncMock(side_effect=APIError(
            code=400,
            response_json=None,
            response=MagicMock()
        ))
        client.client.aio.models.generate_content = mock_generate
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(AIContentAnalysisError) as exc_info:
            await client.generate(req)
        assert "fatal API error" in str(exc_info.value)

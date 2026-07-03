import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import openai

from src.analyzers.url.ai_content_analysis.models import PromptRequest, LLMOutput
from src.analyzers.url.ai_content_analysis.exceptions import (
    AIContentAnalysisError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMRateLimitError,
)
from src.analyzers.url.ai_content_analysis.client.openai_client import OpenAIClient
from src.analyzers.url.ai_content_analysis.client.retry import execute_with_retry, MAX_RETRIES


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


# ─── OpenAI Client Payload Assembly & Configuration Tests ───────────────────────

class TestOpenAIClientPayload:
    @pytest.mark.anyio
    async def test_generate_text_only(self):
        client = OpenAIClient(api_key="test_key")
        
        # Mock completions endpoint
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Analysis Result String"
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        
        mock_create = AsyncMock(return_value=mock_response)
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="system instructions",
            user_prompt="user instructions",
            response_schema=LLMOutput,
            vision_enabled=False
        )
        
        result = await client.generate(req)
        assert result == "Analysis Result String"
        
        # Verify calls and mapping
        mock_create.assert_called_once()
        kwargs = mock_create.call_args[1]
        assert kwargs["temperature"] == 0.0
        assert len(kwargs["messages"]) == 2
        assert kwargs["messages"][0] == {"role": "system", "content": "system instructions"}
        assert kwargs["messages"][1] == {"role": "user", "content": "user instructions"}

    @pytest.mark.anyio
    async def test_generate_multimodal_vision(self):
        client = OpenAIClient(api_key="test_key")
        
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Vision Result String"
        mock_response.choices = [mock_choice]
        mock_response.usage = None
        
        mock_create = AsyncMock(return_value=mock_response)
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="system instructions",
            user_prompt="user instructions",
            response_schema=LLMOutput,
            vision_enabled=True,
            screenshot_path="base64payload"
        )
        
        result = await client.generate(req)
        assert result == "Vision Result String"
        
        # Verify message assembly structure
        kwargs = mock_create.call_args[1]
        assert len(kwargs["messages"]) == 2
        assert kwargs["messages"][1]["role"] == "user"
        content = kwargs["messages"][1]["content"]
        assert len(content) == 2
        assert content[0] == {"type": "text", "text": "user instructions"}
        assert content[1] == {
            "type": "image_url",
            "image_url": {
                "url": "data:image/png;base64,base64payload"
            }
        }


# ─── OpenAI Client Error Handling & Translation Tests ─────────────────────────

class TestOpenAIClientErrorHandling:
    @pytest.mark.anyio
    async def test_rate_limit_error_translation(self):
        client = OpenAIClient(api_key="test_key")
        
        mock_create = AsyncMock(side_effect=openai.RateLimitError(
            message="Rate limit exceeded",
            response=MagicMock(),
            body=None
        ))
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMRateLimitError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_timeout_error_translation(self):
        client = OpenAIClient(api_key="test_key")
        
        mock_create = AsyncMock(side_effect=openai.APITimeoutError(
            request=MagicMock()
        ))
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMTimeoutError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_connection_error_translation(self):
        client = OpenAIClient(api_key="test_key")
        
        mock_create = AsyncMock(side_effect=openai.APIConnectionError(
            request=MagicMock()
        ))
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMConnectionError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_status_error_transient_translation(self):
        client = OpenAIClient(api_key="test_key")
        
        # 503 Service Unavailable represents a transient server failure
        mock_create = AsyncMock(side_effect=openai.APIStatusError(
            message="Service Unavailable",
            response=MagicMock(status_code=503),
            body=None
        ))
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(LLMConnectionError):
            await client.generate(req)

    @pytest.mark.anyio
    async def test_status_error_fatal_translation(self):
        client = OpenAIClient(api_key="test_key")
        
        # 400 Bad Request represents a fatal parameter error
        mock_create = AsyncMock(side_effect=openai.APIStatusError(
            message="Bad Request",
            response=MagicMock(status_code=400),
            body=None
        ))
        client.client.chat.completions.create = mock_create
        
        req = PromptRequest(
            system_prompt="sys", user_prompt="usr",
            response_schema=LLMOutput, vision_enabled=False
        )
        
        with pytest.raises(AIContentAnalysisError) as exc_info:
            await client.generate(req)
        assert "fatal status error" in str(exc_info.value)

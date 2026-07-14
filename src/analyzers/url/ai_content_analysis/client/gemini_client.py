import time
import base64
import logging
import asyncio
import httpx
from google import genai
from google.genai import types
from google.genai.errors import APIError
from typing import Optional

from src.analyzers.url.ai_content_analysis.config import config
from src.analyzers.url.ai_content_analysis.models import PromptRequest
from src.analyzers.url.ai_content_analysis.client.llm_client import BaseLLMClient
from src.analyzers.url.ai_content_analysis.client.retry import execute_with_retry
from src.analyzers.url.ai_content_analysis.exceptions import (
    AIContentAnalysisError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMQuotaExhaustedError,
)


logger = logging.getLogger(__name__)

class GeminiClient(BaseLLMClient):
    """Concrete production implementation of BaseLLMClient using Google Gemini genai SDK."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or config.gemini_api_key
        logger.info(f"[GeminiClient] Initializing with API Key: {'*' * 30}{self.api_key[-4:]}")
        # Initialize client. The new SDK requires passing api_key directly
        # or setting GEMINI_API_KEY env var.
        self.client = genai.Client(api_key=self.api_key)

    async def generate(self, request: PromptRequest) -> str:
        """Asynchronously triggers the LLM generation flow on the Gemini client wrapped with a retry policy."""
        try:
            logger.info(f"Attempting content generation with primary model: {config.model_name}")
            return await execute_with_retry(self._generate_once, request, model_name=config.model_name)
        except (LLMQuotaExhaustedError, LLMRateLimitError, LLMConnectionError) as e:
            if config.backup_model_name and config.backup_model_name != config.model_name:
                logger.warning(
                    f"Primary model {config.model_name} failed: {str(e)}. "
                    f"Initiating fallback to backup model: {config.backup_model_name}"
                )
                try:
                    return await execute_with_retry(self._generate_once, request, model_name=config.backup_model_name)
                except Exception as backup_err:
                    logger.error(f"Backup model {config.backup_model_name} also failed: {str(backup_err)}")
                    raise backup_err
            raise e

    async def _generate_once(self, request: PromptRequest, model_name: Optional[str] = None) -> str:
        """Helper executing a single call to the live Gemini API endpoint."""
        selected_model = model_name or config.model_name

        # 1. Prepare contents array structure (User Context)
        contents = [request.user_prompt]

        if request.vision_enabled and request.screenshot_base64:
            # Build unified multimodal payload using types.Part
            try:
                decoded_image = base64.b64decode(request.screenshot_base64)
                image_part = types.Part.from_bytes(
                    data=decoded_image,
                    mime_type="image/png"
                )
                contents.append(image_part)
            except Exception as e:
                raise AIContentAnalysisError(f"Failed to decode base64 screenshot payload: {str(e)}") from e

        # 2. Build configuration with timeout limits and response schema
        # Note: types.HttpOptions timeout is in milliseconds
        timeout_ms = int(config.timeout_seconds * 1000) if config.timeout_seconds else None
        gen_config = types.GenerateContentConfig(
            system_instruction=request.system_prompt,
            temperature=config.temperature,
            max_output_tokens=config.max_tokens,
            response_mime_type="application/json",
            response_schema=request.response_schema,
            http_options=types.HttpOptions(timeout=timeout_ms)
        )

        # 3. Call Gemini async models API and measure execution duration
        start_time = time.perf_counter()
        try:
            # client.aio.models.generate_content is the official async content generation method
            response = await self.client.aio.models.generate_content(
                model=selected_model,
                contents=contents,
                config=gen_config
            )
            duration = time.perf_counter() - start_time

            response_text = response.text or ""

            # 4. Safe telemetry log mapping (No prompts, keys, or screenshots)
            usage = getattr(response, "usage_metadata", None)
            usage_info = {
                "prompt_tokens": getattr(usage, "prompt_token_count", 0),
                "completion_tokens": getattr(usage, "candidates_token_count", getattr(usage, "response_token_count", 0)),
                "total_tokens": getattr(usage, "total_token_count", 0)
            } if usage else None

            logger.info(
                f"LLM request completed. model_name={selected_model} "
                f"request_duration={duration:.4f}s token_usage={usage_info}"
            )

            # Return raw response content directly without validation or json transformation
            return response_text

        # 5. Exception translation mapping layer to keep orchestrator decoupled
        except APIError as e:
            err_msg_lower = str(e).lower()
            is_quota = (
                "quota" in err_msg_lower
                or "resource_exhausted" in err_msg_lower
                or "resource exceeded" in err_msg_lower
                or "limit exceeded" in err_msg_lower
            )
            if e.code == 429:
                if is_quota:
                    raise LLMQuotaExhaustedError(f"Gemini quota exhausted error: {str(e)}") from e
                raise LLMRateLimitError(f"Gemini rate limit error: {str(e)}") from e
            elif e.code == 408:
                raise LLMTimeoutError(f"Gemini timeout error: {str(e)}") from e
            elif e.code and e.code >= 500:
                raise LLMConnectionError(f"Gemini transient server error ({e.code}): {str(e)}") from e
            else:
                # Fatal errors (400 bad parameters, 401 bad authentication, 403 authorization)
                raise AIContentAnalysisError(f"Gemini fatal API error ({e.code}): {str(e)}") from e
        except (httpx.TimeoutException, asyncio.TimeoutError) as e:
            raise LLMTimeoutError(f"Gemini client timeout error: {str(e)}") from e
        except httpx.RequestError as e:
            raise LLMConnectionError(f"Gemini client connection error: {str(e)}") from e
        except Exception as e:
            if isinstance(e, AIContentAnalysisError):
                raise
            raise AIContentAnalysisError(f"Unexpected error encountered during LLM operation: {str(e)}") from e

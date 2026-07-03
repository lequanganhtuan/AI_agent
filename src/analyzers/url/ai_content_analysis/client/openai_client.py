import time
import logging
import openai
from openai import AsyncOpenAI
from typing import Optional

from src.analyzers.url.ai_content_analysis.config import config
from src.analyzers.url.ai_content_analysis.models import PromptRequest
from src.analyzers.url.ai_content_analysis.client.llm_client import BaseLLMClient
from src.analyzers.url.ai_content_analysis.exceptions import (
    AIContentAnalysisError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMRateLimitError,
)

logger = logging.getLogger(__name__)

class OpenAIClient(BaseLLMClient):
    """Concrete production implementation of BaseLLMClient using OpenAI SDK."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or config.openai_api_key
        # Initialize client with timeout from configuration boundary
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            timeout=config.timeout_seconds
        )

    async def generate(self, request: PromptRequest) -> str:
        """Asynchronously triggers the LLM generation flow on the OpenAI client.
        
        Sequences system instructions, user context, and optionally multimodal screenshot
        image payload from base64 directly, bypassing secondary file I/O operations.
        """
        # 1. Prepare payload message assembly structure
        messages = [
            {"role": "system", "content": request.system_prompt}
        ]

        if request.vision_enabled and request.screenshot_path:
            # Build unified multimodal payload
            user_content = [
                {
                    "type": "text",
                    "text": request.user_prompt
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/png;base64,{request.screenshot_path}"
                    }
                }
            ]
            messages.append({"role": "user", "content": user_content})
        else:
            messages.append({"role": "user", "content": request.user_prompt})

        # 2. Call OpenAI API and measure execution duration
        start_time = time.perf_counter()
        try:
            response = await self.client.chat.completions.create(
                model=config.model_name,
                messages=messages,
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            duration = time.perf_counter() - start_time

            if not response.choices:
                raise AIContentAnalysisError("API response returned no generation choices.")

            response_text = response.choices[0].message.content or ""

            # 3. Safe telemetry log mapping (No prompts, keys, or screenshots)
            token_usage = getattr(response, "usage", None)
            usage_info = {
                "prompt_tokens": token_usage.prompt_tokens,
                "completion_tokens": token_usage.completion_tokens,
                "total_tokens": token_usage.total_tokens
            } if token_usage else None

            logger.info(
                f"LLM request completed. model_name={config.model_name} "
                f"request_duration={duration:.4f}s token_usage={usage_info}"
            )

            # Return raw response content directly without validation or json transformation
            return response_text

        # 4. Exception translation mapping layer to keep orchestrator decoupled
        except openai.RateLimitError as e:
            raise LLMRateLimitError(f"OpenAI rate limit error: {str(e)}") from e
        except openai.APITimeoutError as e:
            raise LLMTimeoutError(f"OpenAI timeout error: {str(e)}") from e
        except openai.APIConnectionError as e:
            raise LLMConnectionError(f"OpenAI connection failure: {str(e)}") from e
        except openai.APIStatusError as e:
            if e.status_code >= 500:
                raise LLMConnectionError(f"OpenAI transient server error ({e.status_code}): {str(e)}") from e
            elif e.status_code == 429:
                raise LLMRateLimitError(f"OpenAI transient rate limit error ({e.status_code}): {str(e)}") from e
            else:
                # Fatal errors (400 bad parameters/payloads, 401 bad authentication, 403 authorization)
                raise AIContentAnalysisError(f"OpenAI fatal status error ({e.status_code}): {str(e)}") from e
        except openai.APIError as e:
            raise AIContentAnalysisError(f"OpenAI API generic exception: {str(e)}") from e
        except Exception as e:
            if isinstance(e, AIContentAnalysisError):
                raise
            raise AIContentAnalysisError(f"Unexpected error encountered during LLM operation: {str(e)}") from e

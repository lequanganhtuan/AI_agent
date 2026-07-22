import asyncio
import random
import logging
from typing import Callable, TypeVar, Any

from src.analyzers.url.ai_content_analysis.exceptions import (
    LLMRateLimitError,
    LLMTimeoutError,
    LLMConnectionError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Immutable maximum retry ceiling constraint
MAX_RETRIES = 3
INITIAL_DELAY_SECONDS = 1.0
BACKOFF_FACTOR = 2.0

async def execute_with_retry(
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any
) -> Any:
    """Executes a function with exponential backoff and randomized jitter retry logic.
    
    Retries only transient errors: LLMRateLimitError, LLMTimeoutError, LLMConnectionError.
    Ignores and propagates fatal exceptions immediately.
    """
    delay = INITIAL_DELAY_SECONDS
    last_exception = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return await func(*args, **kwargs)
        except (LLMRateLimitError, LLMTimeoutError, LLMConnectionError) as e:
            last_exception = e
            if attempt == MAX_RETRIES:
                logger.error(
                    f"LLM request failed after max retry limit of {MAX_RETRIES} attempts. Error: {e}"
                )
                raise

            # Apply backoff and randomized jitter to avoid synchronization storms
            sleep_time = delay * (0.5 + random.random())
            logger.warning(
                f"Transient LLM exception encountered (attempt {attempt}/{MAX_RETRIES}): {e}. "
                f"Retrying in {sleep_time:.2f} seconds..."
            )
            await asyncio.sleep(sleep_time)
            delay *= BACKOFF_FACTOR

    if last_exception:
        raise last_exception
    raise RuntimeError("Retry loop exited without a result or exception.")

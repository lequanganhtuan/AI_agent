import time
import logging
import asyncio
import concurrent.futures
from typing import Any
from pydantic import BaseModel
from src.agents.state import URLAnalysisState

logger = logging.getLogger(__name__)

global_executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)

class ToolResult(BaseModel):
    success: bool
    data: Any = None
    error: str | None = None
    retryable: bool = False
    duration: float = 0.0

class BaseTool:
    async def run(self, state: URLAnalysisState) -> ToolResult:
        start_time = time.perf_counter()
        try:
            logger.info(f"Executing tool: {self.__class__.__name__}")
            if asyncio.iscoroutinefunction(self._execute):
                result_data = await self._execute(state)
            else:
                result_data = self._execute(state)
            duration = time.perf_counter() - start_time
            
            if isinstance(result_data, ToolResult):
                result_data.duration = duration
                return result_data
                
            return ToolResult(success=True, data=result_data, duration=duration)
            
        except Exception as e:
            duration = time.perf_counter() - start_time
            logger.exception(f"Error executing tool {self.__class__.__name__}: {str(e)}")
            retryable = self._is_retryable(e)
            return ToolResult(
                success=False,
                error=str(e),
                retryable=retryable,
                duration=duration
            )

    async def _execute(self, state: URLAnalysisState) -> Any:
        raise NotImplementedError("Subclasses must implement _execute")

    def _is_retryable(self, exc: Exception) -> bool:
        exc_name = type(exc).__name__
        transient_keywords = ["Timeout", "Connection", "TimeoutError", "HTTPError", "RateLimit"]
        return any(kw in exc_name for kw in transient_keywords)

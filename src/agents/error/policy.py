import logging
from src.agents.state.enums import NodeName
from .strategy import ErrorAction, ErrorDecision

logger = logging.getLogger(__name__)

class ErrorPolicy:
    """Centralized Error Policy engine governing Agent execution flow on failures."""
    
    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries

    def classify_error(self, error_message: str, retryable: bool) -> str:
        """Classifies a raw error message into a standardized category."""
        msg = error_message.lower() if error_message else ""
        if "validation" in msg or "invalid" in msg or "value_error" in msg:
            return "ValidationError"
        if "timeout" in msg or "deadline" in msg or "timed out" in msg:
            return "TimeoutError"
        if "rate limit" in msg or "quota exceeded" in msg or "429" in msg or "rate_limit" in msg:
            return "RateLimitError"
        if "network" in msg or "connection" in msg or "dns" in msg or "http" in msg or "socket" in msg:
            return "NetworkError"
        if retryable:
            return "ToolExecutionError"
        return "InternalError"

    def handle(self, error_message: str, node: NodeName, retry_count: int, retryable: bool) -> ErrorDecision:
        """Determines the recovery action for a given node failure."""
        error_type = self.classify_error(error_message, retryable)
        
        # 1. Validation failures are always fatal -> STOP
        if error_type == "ValidationError" or node == NodeName.VALIDATE:
            logger.error(f"[ErrorPolicy] Fatal Validation error at {node.value}: {error_message}")
            return ErrorDecision(action=ErrorAction.STOP, error_type=error_type, message=error_message)

        # 2. Store node failure is also fatal -> STOP
        if node == NodeName.STORE:
            logger.error(f"[ErrorPolicy] Fatal Persistence error at {node.value}: {error_message}")
            return ErrorDecision(action=ErrorAction.STOP, error_type=error_type, message=error_message)

        # 3. For retryable errors, check if we can retry
        if retryable and retry_count < self.max_retries:
            logger.warning(f"[ErrorPolicy] Retryable error ({error_type}) at {node.value}. Attempt {retry_count + 1}/{self.max_retries}.")
            return ErrorDecision(action=ErrorAction.RETRY, error_type=error_type, message=error_message)

        # 4. In all other cases (e.g. non-critical static, threat, dynamic, AI nodes),
        # we gracefully degrade and continue (or skip) rather than halting the workflow.
        logger.warning(f"[ErrorPolicy] Non-fatal error ({error_type}) at {node.value}. Bypassing error, routing to next step.")
        return ErrorDecision(action=ErrorAction.CONTINUE, error_type=error_type, message=error_message)

# Global policy instance
error_policy = ErrorPolicy()

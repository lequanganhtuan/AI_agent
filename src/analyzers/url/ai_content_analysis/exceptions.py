class AIContentAnalysisError(Exception):
    """Base exception for all AI Content Analysis module errors."""
    pass

class LLMConnectionError(AIContentAnalysisError):
    """Raised when communication with the LLM API fails due to network or connection issues."""
    pass

class LLMTimeoutError(AIContentAnalysisError):
    """Raised when the LLM API request times out."""
    pass

class LLMRateLimitError(AIContentAnalysisError):
    """Raised when the LLM API rate limit is exceeded."""
    pass

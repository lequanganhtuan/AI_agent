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

class LLMResponseParseError(AIContentAnalysisError):
    """Raised when the raw LLM response fails structural string deserialization or schema mapping."""
    pass

class LLMResponseValidationError(AIContentAnalysisError):
    """Raised when semantic/logical validation rules fail verification on the LLM output."""
    pass


import os
from pydantic import BaseModel, Field
from src.core.settings import settings

class AIAnalysisConfig(BaseModel):
    """Configuration settings specific to the AI Content Analysis module."""
    
    # API Keys from centralized core setting
    gemini_api_key: str | None = Field(default=settings.gemini_api_key)
    
    # Deployment model target
    model_name: str = Field(default="gemini-2.5-flash-lite")
    
    # Temperature (deterministic)
    temperature: float = Field(default=0.0)
    
    # Max output token generation window
    max_tokens: int = Field(default=2000)
    
    # HTTP Client request timeout limit
    timeout_seconds: float = Field(default=30.0)


# Active configuration instance
config = AIAnalysisConfig()

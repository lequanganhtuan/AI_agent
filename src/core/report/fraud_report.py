from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime

from src.core.models import (
    ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult,
    DynamicAnalysisResult
)
from src.analyzers.url.ai_content_analysis.models import (
    ContentAnalysisResult, AISignal, AIRisk
)

class FraudAIAnalysisReport(BaseModel):
    """Pruned version of AIAnalysisResult for report persistence."""
    content: Optional[ContentAnalysisResult] = None
    signals: List[AISignal] = Field(default_factory=list)
    risk: Optional[AIRisk] = None
    error: Optional[str] = None
    system_prompt: Optional[str] = None
    user_prompt: Optional[str] = None


class FraudReport(BaseModel):
    """Decoupled Report structure representing a clean, persisted threat scan."""
    id: str  # Document UUID
    cache_key: str
    url: str
    normalized_url: str
    scanned_at: datetime
    
    validation: ValidationResult
    static: StaticAnalysisResult
    threat_intelligence: ThreatIntelligenceResult = Field(alias="threat_intel")
    dynamic: Optional[DynamicAnalysisResult] = None
    ai: Optional[FraudAIAnalysisReport] = None

    model_config = ConfigDict(
        populate_by_name=True
    )

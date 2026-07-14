from pydantic import BaseModel
from src.core.models import (
    ValidationResult,
    StaticAnalysisResult,
    ThreatIntelligenceResult,
    DynamicAnalysisResult
)
from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult

class AnalysisState(BaseModel):
    raw_url: str | None = None
    normalized_url: str | None = None
    final_url: str | None = None
    validation: ValidationResult | None = None
    static: StaticAnalysisResult | None = None
    threat_intelligence: ThreatIntelligenceResult | None = None
    dynamic: DynamicAnalysisResult | None = None
    ai: AIAnalysisResult | None = None

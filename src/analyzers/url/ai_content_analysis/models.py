from enum import Enum
from typing import Any, Optional, Type
from pydantic import BaseModel, ConfigDict, Field

# Strict Enum Definitions
class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FraudCategory(str, Enum):
    PHISHING = "PHISHING"
    SCAM = "SCAM"
    MALWARE = "MALWARE"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    LEGITIMATE = "LEGITIMATE"
    OTHER = "OTHER"

class RecommendedAction(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    MONITOR = "MONITOR"
    ALLOW = "ALLOW"

class AISignalType(str, Enum):
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    DECEPTIVE_LOGOS = "DECEPTIVE_LOGOS"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    URGENCY_DARK_PATTERNS = "URGENCY_DARK_PATTERNS"
    SUSPICIOUS_LINKS = "SUSPICIOUS_LINKS"
    INSECURE_FORM = "INSECURE_FORM"
    MALICIOUS_DISTR = "MALICIOUS_DISTR"
    EXCESSIVE_ADS = "EXCESSIVE_ADS"
    OTHER = "OTHER"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Model 1: AIAnalysisInput
class AIAnalysisInput(BaseModel):
    url: str
    final_url: str
    page_title: str
    extracted_text: str
    screenshot_path: Optional[str] = None
    legitimate_domain: Optional[str] = None
    static_summary: str
    threat_summary: str
    dynamic_summary: str
    important_signals: list[str]
    metadata: dict[str, Any]


# Model 2: PromptRequest
class PromptRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    system_prompt: str
    user_prompt: str
    response_schema: Type[BaseModel]
    vision_enabled: bool
    screenshot_path: Optional[str] = None



# Model 3: LLMOutput
class LLMOutput(BaseModel):
    website_purpose: str
    is_phishing: bool
    fraud_category: FraudCategory
    detected_brand: Optional[str] = None
    brand_confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: list[str]
    summary: str
    recommended_action: RecommendedAction
    risk_level: RiskLevel
    findings: list[str]


# Model 4: ContentAnalysisResult
class ContentAnalysisResult(BaseModel):
    website_purpose: str
    detected_brand: Optional[str] = None
    fraud_category: FraudCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    reasoning: list[str]
    recommended_action: RecommendedAction


# Model 5: AISignal
class AISignal(BaseModel):
    signal: AISignalType
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str


# Model 6: AIRisk
class AIRisk(BaseModel):
    score: float
    level: RiskLevel
    summary: str


# Model 7: AIAnalysisResult
class AIAnalysisResult(BaseModel):
    content: ContentAnalysisResult
    signals: list[AISignal]
    risk: AIRisk

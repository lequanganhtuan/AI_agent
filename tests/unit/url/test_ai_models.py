import pytest
from pydantic import BaseModel
from src.analyzers.url.ai_content_analysis.models import (
    RiskLevel,
    FraudCategory,
    RecommendedAction,
    AISignalType,
    Severity,
    AIAnalysisInput,
    PromptRequest,
    LLMOutput,
    ContentAnalysisResult,
    AISignal,
    AIRisk,
    AIAnalysisResult
)

def test_enums():
    assert RiskLevel.HIGH == "HIGH"
    assert FraudCategory.PHISHING == "PHISHING"
    assert RecommendedAction.BLOCK == "BLOCK"
    assert AISignalType.BRAND_IMPERSONATION == "BRAND_IMPERSONATION"
    assert Severity.CRITICAL == "CRITICAL"

def test_ai_analysis_input():
    input_data = {
        "url": "http://suspicious.site",
        "final_url": "https://suspicious.site/login",
        "page_title": "Fake Login",
        "extracted_text": "Please enter your password",
        "screenshot_path": "artifacts/screenshots/abc.png",
        "legitimate_domain": "paypal.com",
        "static_summary": "High static risk",
        "threat_summary": "Zero blacklists",
        "dynamic_summary": "Contains password fields",
        "important_signals": ["SUSPICIOUS_KEYWORD", "PASSWORD_FIELD"],
        "metadata": {"ip": "1.2.3.4"}
    }
    model = AIAnalysisInput(**input_data)
    assert model.url == "http://suspicious.site"
    assert model.metadata["ip"] == "1.2.3.4"

def test_prompt_request():
    class DummySchema(BaseModel):
        test_field: str
        
    req = PromptRequest(
        system_prompt="You are a helper",
        user_prompt="Analyze this",
        response_schema=DummySchema,
        vision_enabled=True
    )
    assert req.vision_enabled is True
    assert req.response_schema == DummySchema

def test_llm_output():
    output_data = {
        "website_purpose": "Impersonating banking login portal.",
        "is_phishing": True,
        "fraud_category": FraudCategory.PHISHING,
        "detected_brand": "Chase Bank",
        "brand_confidence": 0.95,
        "reasoning": ["Uses Chase logo", "Hosted on unrecognized domain"],
        "summary": "Phishing site Targeting Chase Bank",
        "recommended_action": RecommendedAction.BLOCK,
        "risk_level": RiskLevel.HIGH,
        "findings": ["Deceptive branding"]
    }
    model = LLMOutput(**output_data)
    assert model.fraud_category == FraudCategory.PHISHING
    assert model.recommended_action == RecommendedAction.BLOCK
    assert model.risk_level == RiskLevel.HIGH

def test_content_analysis_result():
    res_data = {
        "website_purpose": "E-commerce portal",
        "detected_brand": None,
        "fraud_category": FraudCategory.LEGITIMATE,
        "confidence": 0.99,
        "summary": "Clean website",
        "reasoning": ["No threats found"],
        "recommended_action": RecommendedAction.ALLOW
    }
    model = ContentAnalysisResult(**res_data)
    assert model.fraud_category == FraudCategory.LEGITIMATE
    assert model.confidence == 0.99

def test_ai_signal():
    sig = AISignal(
        signal=AISignalType.CREDENTIAL_HARVESTING,
        severity=Severity.HIGH,
        confidence=0.9,
        description="Login form detected on untrusted domain"
    )
    assert sig.signal == AISignalType.CREDENTIAL_HARVESTING
    assert sig.severity == Severity.HIGH

def test_ai_risk():
    risk = AIRisk(
        score=85,
        level=RiskLevel.HIGH,
        summary="High probability of phishing impersonating Chase Bank"
    )
    assert risk.score == 85
    assert risk.level == RiskLevel.HIGH

def test_ai_analysis_result():
    res = AIAnalysisResult(
        content=ContentAnalysisResult(
            website_purpose="Login page",
            detected_brand="Google",
            fraud_category=FraudCategory.BRAND_IMPERSONATION,
            confidence=0.95,
            summary="Impersonates Google login",
            reasoning=["Google branding used"],
            recommended_action=RecommendedAction.BLOCK
        ),
        signals=[
            AISignal(
                signal=AISignalType.BRAND_IMPERSONATION,
                severity=Severity.HIGH,
                confidence=0.95,
                description="Google logo usage"
            )
        ],
        risk=AIRisk(
            score=90,
            level=RiskLevel.HIGH,
            summary="Impersonates Google login"
        )
    )
    assert res.content.detected_brand == "Google"
    assert len(res.signals) == 1
    assert res.risk.score == 90

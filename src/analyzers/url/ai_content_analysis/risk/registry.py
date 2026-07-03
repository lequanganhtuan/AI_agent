from src.analyzers.url.ai_content_analysis.models import AISignalType, Severity

# Weights assigned to each signal type
SIGNAL_WEIGHT_MAP = {
    AISignalType.BRAND_IMPERSONATION: 35,
    AISignalType.VISUAL_CLONING: 25,
    AISignalType.FAKE_LOGIN_PAGE: 40,
    AISignalType.DATA_HARVESTING: 45,
    AISignalType.SENSITIVE_INFORMATION_REQUEST: 35,
    AISignalType.FAKE_TRUST_SIGNAL: 15,
    AISignalType.URGENCY_LANGUAGE: 15,
}

# Multipliers assigned to each severity level
SEVERITY_MULTIPLIER = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 1.2,
    Severity.HIGH: 1.5,
    Severity.CRITICAL: 2.0
}

# Score threshold limits mapping to RiskLevel
LOW_MAX = 25
MEDIUM_MAX = 50
HIGH_MAX = 75
CRITICAL_MAX = 100

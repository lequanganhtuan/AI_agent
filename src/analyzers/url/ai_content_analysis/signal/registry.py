from src.analyzers.url.ai_content_analysis.models import FraudCategory, AISignalType, Severity

# Mappings from FraudCategory to (AISignalType, Severity)
FRAUD_CATEGORY_SIGNAL_MAP = {
    FraudCategory.PHISHING: (AISignalType.DATA_HARVESTING, Severity.HIGH),
    FraudCategory.SCAM: (AISignalType.DATA_HARVESTING, Severity.MEDIUM),
    FraudCategory.BRAND_IMPERSONATION: (AISignalType.BRAND_IMPERSONATION, Severity.HIGH),
    FraudCategory.MALWARE: (AISignalType.DATA_HARVESTING, Severity.CRITICAL),
    FraudCategory.OTHER: (AISignalType.DATA_HARVESTING, Severity.MEDIUM),
}

# Signal type default severity mapping (to prevent hardcoding severity in mapper)
SIGNAL_SEVERITY_MAP = {
    AISignalType.BRAND_IMPERSONATION: Severity.HIGH,
    AISignalType.VISUAL_CLONING: Severity.HIGH,
    AISignalType.URGENCY_LANGUAGE: Severity.MEDIUM,
    AISignalType.FAKE_TRUST_SIGNAL: Severity.LOW,
    AISignalType.DATA_HARVESTING: Severity.HIGH,
    AISignalType.SENSITIVE_INFORMATION_REQUEST: Severity.HIGH,
    AISignalType.FAKE_LOGIN_PAGE: Severity.HIGH,
}

# Keyword mapping table to scan findings and reasoning texts
KEYWORD_SIGNAL_MAP = {
    "login": AISignalType.FAKE_LOGIN_PAGE,
    "signin": AISignalType.FAKE_LOGIN_PAGE,
    "credential": AISignalType.DATA_HARVESTING,
    "password": AISignalType.DATA_HARVESTING,
    "harvest": AISignalType.DATA_HARVESTING,
    "bank": AISignalType.BRAND_IMPERSONATION,
    "impersonate": AISignalType.BRAND_IMPERSONATION,
    "spoof": AISignalType.BRAND_IMPERSONATION,
    "urgent": AISignalType.URGENCY_LANGUAGE,
    "hurry": AISignalType.URGENCY_LANGUAGE,
    "countdown": AISignalType.URGENCY_LANGUAGE,
    "timer": AISignalType.URGENCY_LANGUAGE,
    "trust badge": AISignalType.FAKE_TRUST_SIGNAL,
    "security seal": AISignalType.FAKE_TRUST_SIGNAL,
    "trust": AISignalType.FAKE_TRUST_SIGNAL,
    "badge": AISignalType.FAKE_TRUST_SIGNAL,
    "sensitive": AISignalType.SENSITIVE_INFORMATION_REQUEST,
    "ssn": AISignalType.SENSITIVE_INFORMATION_REQUEST,
    "social security": AISignalType.SENSITIVE_INFORMATION_REQUEST,
    "credit card": AISignalType.SENSITIVE_INFORMATION_REQUEST,
    "clone": AISignalType.VISUAL_CLONING,
    "copy": AISignalType.VISUAL_CLONING,
    "visual": AISignalType.VISUAL_CLONING,
}

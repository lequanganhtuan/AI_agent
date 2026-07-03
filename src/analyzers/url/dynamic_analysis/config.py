from pydantic_settings import BaseSettings
from src.core.models import DynamicAnalysisResult

class DynamicAnalysisConfig(BaseSettings):
    # Playwright browser engine configurations
    TIMEOUT_MS: int = 30000
    VIEWPORT_WIDTH: int = 1280
    VIEWPORT_HEIGHT: int = 720
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    IGNORE_HTTPS_ERRORS: bool = True
    HEADLESS: bool = True
    NO_SANDBOX: bool = True  # If true, pass --no-sandbox flag to chromium
    WAIT_UNTIL_STRATEGY: str = "load"

    # Form field keyword lists for dynamic analysis
    LOGIN_KEYWORDS: list[str] = ["login", "signin", "log-in", "sign-in"]
    OTP_KEYWORDS: list[str] = ["otp", "one-time-password", "verification_code", "mã_otp", "verificationcode"]
    CCCD_KEYWORDS: list[str] = ["cccd", "national_id", "cmnd", "citizen_id", "identity_card", "số_định_danh", "citizenid"]
    CREDIT_CARD_KEYWORDS: list[str] = ["card_number", "credit_card", "cvv", "expiration_date", "expiry", "cardnumber", "so_the", "card_no", "creditcard"]

    # CDN identification keywords for network analysis
    CDN_KEYWORDS: list[str] = ["cdn", "fastly", "cloudfront", "akamai", "cloudflare", "jsdelivr", "unpkg"]

    # Screenshot collection settings
    SCREENSHOT_DIRECTORY: str = "artifacts/screenshots"
    SCREENSHOT_FULL_PAGE: bool = True
    SCREENSHOT_TYPE: str = "png"  # png or jpeg
    SCREENSHOT_QUALITY: int | None = None  # only applied if screenshot type is jpeg

    # Threshold for redirects
    MULTI_REDIRECT_THRESHOLD: int = 3

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class DynamicSignalType:
    MULTI_REDIRECT = "MULTI_REDIRECT"
    CROSS_DOMAIN_REDIRECT = "CROSS_DOMAIN_REDIRECT"
    PRIVATE_IP_REDIRECT = "PRIVATE_IP_REDIRECT"
    IP_REDIRECT = "IP_REDIRECT"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    
    PASSWORD_FIELD = "PASSWORD_FIELD"
    LOGIN_FORM = "LOGIN_FORM"
    OTP_FIELD = "OTP_FIELD"
    CREDIT_CARD_FIELD = "CREDIT_CARD_FIELD"
    CCCD_FIELD = "CCCD_FIELD"
    HIDDEN_IFRAME = "HIDDEN_IFRAME"
    META_REFRESH = "META_REFRESH"
    EVAL_USAGE = "EVAL_USAGE"
    ATOB_USAGE = "ATOB_USAGE"
    UNESCAPE_USAGE = "UNESCAPE_USAGE"
    EXTERNAL_SCRIPT = "EXTERNAL_SCRIPT"
    
    THIRD_PARTY_DOMAIN = "THIRD_PARTY_DOMAIN"
    CDN_USAGE = "CDN_USAGE"
    API_USAGE = "API_USAGE"
    WEBSOCKET_USAGE = "WEBSOCKET_USAGE"
    FAILED_REQUEST = "FAILED_REQUEST"
    
    # Composite signals
    LOGIN_CREDENTIAL_COLLECTION = "LOGIN_CREDENTIAL_COLLECTION"
    LOGIN_REDIRECT_FLOW = "LOGIN_REDIRECT_FLOW"
    OBFUSCATED_LOGIN_PAGE = "OBFUSCATED_LOGIN_PAGE"
    PAYMENT_COLLECTION = "PAYMENT_COLLECTION"
    
    # Qualitative script analysis signals
    UNLISTED_EXTERNAL_SCRIPT = "UNLISTED_EXTERNAL_SCRIPT"
    IP_ADDRESS_EXTERNAL_SCRIPT = "IP_ADDRESS_EXTERNAL_SCRIPT"
    
    # Deep form attribute signals
    CROSS_DOMAIN_FORM_ACTION = "CROSS_DOMAIN_FORM_ACTION"
    INSECURE_FORM_ACTION = "INSECURE_FORM_ACTION"
    GET_LOGIN_FORM = "GET_LOGIN_FORM"
    EMPTY_FORM_ACTION = "EMPTY_FORM_ACTION"

SIGNAL_SEVERITY: dict[str, str] = {
    DynamicSignalType.MULTI_REDIRECT: Severity.MEDIUM,
    DynamicSignalType.CROSS_DOMAIN_REDIRECT: Severity.MEDIUM,
    DynamicSignalType.PRIVATE_IP_REDIRECT: Severity.CRITICAL,
    DynamicSignalType.IP_REDIRECT: Severity.MEDIUM,
    DynamicSignalType.REDIRECT_LOOP: Severity.CRITICAL,
    
    DynamicSignalType.PASSWORD_FIELD: Severity.MEDIUM,
    DynamicSignalType.LOGIN_FORM: Severity.MEDIUM,
    DynamicSignalType.OTP_FIELD: Severity.MEDIUM,
    DynamicSignalType.CREDIT_CARD_FIELD: Severity.MEDIUM,
    DynamicSignalType.CCCD_FIELD: Severity.MEDIUM,
    DynamicSignalType.HIDDEN_IFRAME: Severity.MEDIUM,
    DynamicSignalType.META_REFRESH: Severity.MEDIUM,
    DynamicSignalType.EVAL_USAGE: Severity.MEDIUM,
    DynamicSignalType.ATOB_USAGE: Severity.LOW,
    DynamicSignalType.UNESCAPE_USAGE: Severity.LOW,
    DynamicSignalType.EXTERNAL_SCRIPT: Severity.LOW,
    
    DynamicSignalType.THIRD_PARTY_DOMAIN: Severity.LOW,
    DynamicSignalType.CDN_USAGE: Severity.LOW,
    DynamicSignalType.API_USAGE: Severity.LOW,
    DynamicSignalType.WEBSOCKET_USAGE: Severity.LOW,
    DynamicSignalType.FAILED_REQUEST: Severity.LOW,
    
    # Severity for new signals
    DynamicSignalType.LOGIN_CREDENTIAL_COLLECTION: Severity.HIGH,
    DynamicSignalType.LOGIN_REDIRECT_FLOW: Severity.HIGH,
    DynamicSignalType.OBFUSCATED_LOGIN_PAGE: Severity.HIGH,
    DynamicSignalType.PAYMENT_COLLECTION: Severity.HIGH,
    DynamicSignalType.UNLISTED_EXTERNAL_SCRIPT: Severity.MEDIUM,
    DynamicSignalType.IP_ADDRESS_EXTERNAL_SCRIPT: Severity.HIGH,
    DynamicSignalType.CROSS_DOMAIN_FORM_ACTION: Severity.HIGH,
    DynamicSignalType.INSECURE_FORM_ACTION: Severity.HIGH,
    DynamicSignalType.GET_LOGIN_FORM: Severity.HIGH,
    DynamicSignalType.EMPTY_FORM_ACTION: Severity.MEDIUM,
}

DYNAMIC_SIGNAL_WEIGHTS: dict[str, int] = {
    DynamicSignalType.PASSWORD_FIELD: 25,
    DynamicSignalType.LOGIN_FORM: 10,
    DynamicSignalType.OTP_FIELD: 30,
    DynamicSignalType.CREDIT_CARD_FIELD: 35,
    DynamicSignalType.CCCD_FIELD: 30,
    DynamicSignalType.HIDDEN_IFRAME: 15,
    DynamicSignalType.META_REFRESH: 15,
    DynamicSignalType.EVAL_USAGE: 15,
    DynamicSignalType.ATOB_USAGE: 5,
    DynamicSignalType.UNESCAPE_USAGE: 5,
    DynamicSignalType.EXTERNAL_SCRIPT: 5,
    DynamicSignalType.MULTI_REDIRECT: 20,
    DynamicSignalType.CROSS_DOMAIN_REDIRECT: 15,
    DynamicSignalType.IP_REDIRECT: 20,
    DynamicSignalType.PRIVATE_IP_REDIRECT: 80,
    DynamicSignalType.REDIRECT_LOOP: 80,
    DynamicSignalType.THIRD_PARTY_DOMAIN: 5,
    DynamicSignalType.CDN_USAGE: 0,
    DynamicSignalType.API_USAGE: 5,
    DynamicSignalType.WEBSOCKET_USAGE: 5,
    DynamicSignalType.FAILED_REQUEST: 5,
    
    # Weights for new signals
    DynamicSignalType.LOGIN_CREDENTIAL_COLLECTION: 45,
    DynamicSignalType.LOGIN_REDIRECT_FLOW: 50,
    DynamicSignalType.OBFUSCATED_LOGIN_PAGE: 50,
    DynamicSignalType.PAYMENT_COLLECTION: 50,
    DynamicSignalType.UNLISTED_EXTERNAL_SCRIPT: 15,
    DynamicSignalType.IP_ADDRESS_EXTERNAL_SCRIPT: 40,
    DynamicSignalType.CROSS_DOMAIN_FORM_ACTION: 40,
    DynamicSignalType.INSECURE_FORM_ACTION: 30,
    DynamicSignalType.GET_LOGIN_FORM: 30,
    DynamicSignalType.EMPTY_FORM_ACTION: 15,
}

RISK_THRESHOLDS: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 30,
    "HIGH": 60,
}

class ConfigurationError(ValueError):
    """Raised when dynamic analysis configurations are invalid."""
    pass

# Validate risk thresholds boundary limits
if not (RISK_THRESHOLDS["LOW"] < RISK_THRESHOLDS["MEDIUM"] < RISK_THRESHOLDS["HIGH"]):
    raise ConfigurationError("Invalid risk threshold boundaries in RISK_THRESHOLDS.")

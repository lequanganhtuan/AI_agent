from typing import Optional
from pydantic import BaseModel

class URLComponents(BaseModel):
    scheme: str # http, https, ftp
    subdomain: str # sub, www, blog
    domain: str # google, facebook
    tld: str # com, org, net, vn
    path: str # key-value
    params: dict
    full_domain: str # subdomain + domain + tld
    
class URLMetadata(BaseModel):
    is_ip: bool = False
    is_private_ip: bool = False
    is_punycode: bool = False # fake character
    contains_unicode: bool = False # special character
    
class ValidationResult(BaseModel):
    valid: bool
    normalized_url: str | None = None
    components: URLComponents | None = None
    cache_key: str | None = None
    signals: list[str] = []
    metadata: URLMetadata | None = None
    error_code: str | None = None
    error_message: str | None = None


 # PHASE 2    
class LexicalFeatures(BaseModel):
    url_length: int
    root_domain_length: int
    full_domain_length: int
    subdomain_count: int
    url_special_char_count: int
    digit_ratio_domain: float
    domain_entropy: float
    hyphen_count: int
    url_depth: int
    query_parameter_count: int
    max_path_segment_length: int
    longest_token_length: int
    consecutive_digit_count: int
    
    
class BrandAnalysis(BaseModel):
    detected_brand: str | None = None
    brand_in_subdomain: bool = False
    brand_in_path: bool = False
    legitimate_domain_match: bool = False
    homoglyph_detected: bool = False
    typosquatting_score: float = 0.0
    typosquatting_target: str | None = None
    levenshtein_distance: int | None = None
    
class PatternAnalysis(BaseModel):
    suspicious_keywords: list[str] = []
    suspicious_keyword_count: int = 0
    encoded_character_detected: bool = False
    encoded_character_count: int = 0
    double_extension_detected: bool = False
    suspicious_file_extension: bool = False
    ip_address_url: bool = False
    url_shortener_detected: bool = False
    
class TLDAnalysis(BaseModel):
    tld: str = ""
    risk_level: str = "unknown"
    risk_score: int = 0
    high_risk_tld: bool = False
    medium_risk_tld: bool = False
    low_risk_tld: bool = False
    country_code_tld: bool = False
    
class TyposquattingAnalysis(BaseModel):
    suspicious: bool = False
    target_brand: str | None = None
    target_domain: str | None = None
    similarity_score: float = 0.0
    levenshtein_distance: int | None = None
    homoglyph_detected: bool = False
    keyboard_typo_detected: bool = False

class StaticRiskAnalysis(BaseModel):
    score: int = 0
    risk_level: str = "low"
    triggered_signals: list[str] = []
    summary: list[str] = []
    
class StaticAnalysisResult(BaseModel):
    lexical: LexicalFeatures
    brand: BrandAnalysis
    pattern: PatternAnalysis
    tld: TLDAnalysis
    typosquatting: TyposquattingAnalysis
    risk: StaticRiskAnalysis


# PHASE 3 - Threat Intelligence
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class VirusTotalAnalysis(BaseModel):
    total_engines: int = Field(default=0)
    malicious: int = Field(default=0)
    suspicious: int = Field(default=0)
    harmless: int = Field(default=0)
    undetected: int = Field(default=0)
    categories: list[str] = Field(default_factory=list)
    scan_date: datetime | None = None
    found: bool = False
    error_message: str | None = None


from typing import Any

class GoogleSafeBrowsingAnalysis(BaseModel):
    threat_found: bool = False
    threat_type: str | None = None
    platform_type: str | None = None
    cache_duration: str | None = None
    error_message: str | None = None


class URLHausAnalysis(BaseModel):
    query_status: str
    url_status: str | None = None
    threat: str | None = None
    tags: list[str] = Field(default_factory=list)
    reporter: str | None = None
    first_seen: datetime | None = None
    payloads: list[dict[str, Any]] = Field(default_factory=list)
    error_message: str | None = None


class PhishTankAnalysis(BaseModel):
    in_database: bool = False
    verified: bool = False
    verified_at: datetime | None = None
    phish_detail_url: str | None = None
    error_message: str | None = None


class URLScanAnalysis(BaseModel):
    screenshot_url: str | None = None
    dom_size: int = 0
    redirect_count: int = 0
    external_links: list[str] = Field(default_factory=list)
    ip_address: str | None = None
    country: str | None = None
    malicious_score: int = 0
    tags: list[str] = Field(default_factory=list)
    scan_id: str | None = None
    form_signals: dict[str, Any] = Field(default_factory=dict)
    hosting_intel: dict[str, Any] = Field(default_factory=dict)
    tech_stack: list[str] = Field(default_factory=list)
    network_risk_score: float = 0.0
    form_risk_score: float = 0.0
    hosting_risk_score: float = 0.0
    urlscan_global_score: float = 0.0
    final_local_score: float = 0.0
    error_message: str | None = None

class AbuseIPDBAnalysis(BaseModel):
    ip_address: str = ""
    abuse_score: int = 0
    total_reports: int = 0
    usage_type: Optional[str] = None
    country_code: Optional[str] = None
    domain: Optional[str] = None
    confidence: int = 100
    error_message: str | None = None


class ThreatSignal(BaseModel):
    code: str
    severity: str
    provider: str


class ThreatIntelligenceRisk(BaseModel):
    score: int = 0
    risk_level: str = "low"
    summary: str = ""
    triggered_signals: list[str] = Field(default_factory=list)
    provider_hits: dict[str, bool] = Field(default_factory=dict)
    confidence: float = 1.0


class ThreatIntelligenceResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    virustotal: VirusTotalAnalysis
    google_safe_browsing: GoogleSafeBrowsingAnalysis
    urlscan: URLScanAnalysis
    ip_reputation: AbuseIPDBAnalysis
    risk: ThreatIntelligenceRisk
    urlhaus: URLHausAnalysis | None = None

class PageSnapshot(BaseModel):
    original_url: str
    final_url: str
    status_code: int
    title: str
    html: str
    load_time_ms: float

class DynamicAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: str = "pending"

class AnalysisContext(BaseModel):
    validation: ValidationResult
    static: StaticAnalysisResult
    threat_intelligence: ThreatIntelligenceResult = Field(alias="threat_intel")

    model_config = ConfigDict(
        populate_by_name=True
    )

    
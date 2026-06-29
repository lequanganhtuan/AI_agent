import os

class URLAnalyzerConfig:
    """
    Manages global configuration for the URL Analyzer ecosystem.
    Allows changing values via environment variables without modifying the code.
    """
    MAX_URL_LENGTH = int(os.getenv("URL_MAX_LENGTH", 2048))
    
    OFFICIAL_ALLOWED_SCHEMES = {"http", "https"}
    
    SUSPICIOUS_TLDS = set(os.getenv(
        "SUSPICIOUS_TLDS", 
        "xyz,top,click,zip,icu,pro,buz,vip,mov"
    ).split(","))

    # List of sensitive IPs that must be blocked (Anti-SSRF)
    BLOCKED_METADATA_IPS = {
        "169.254.169.254",  # AWS / Google Cloud Metadata
        "100.100.100.200"   # Alibaba Cloud Metadata
    }
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

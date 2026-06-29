class StaticConfig:
    SPECIAL_CHARS = {
        "-", "_", "@", "=", "%", "&", "+", "~", "?",
    }
    
class BrandConfig:
    BRAND_KEYWORDS = {
        "vietcombank", "techcombank", "vpbank", "mbbank", "acb",
        "sacombank", "bidv", "momo", "zalopay", "shopee", "lazada",
        "tiki", "google", "microsoft", "apple", "facebook", "instagram",
    }

    LEGITIMATE_DOMAINS = {
        "vietcombank": {"vietcombank.com.vn"},
        "techcombank": {"techcombank.com.vn"},
        "vpbank": {"vpbank.com.vn"},
        "mbbank": {"mbbank.com.vn"},
        "momo": {"momo.vn"},
        "zalopay": {"zalopay.vn"},
        "shopee": {"shopee.vn", "shopee.com"},
        "google": {"google.com"},
        "facebook": {"facebook.com"}
    }
    
    # LỖI 2 FIX: Bổ sung danh sách trắng để cứu các link profile chính chủ
    TRUSTED_PLATFORMS = {
        "github.com",
        "facebook.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "youtube.com",
        "medium.com"
    }
    
class PatternConfig:
    SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "verification", "secure",
        "security", "update", "confirm", "account", "banking",
        "wallet", "payment", "authenticate", "recovery", "password",
        "reset", "otp",
    }

    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
        "rebrand.ly", "ow.ly", "is.gd", "buff.ly",
    }

    SUSPICIOUS_FILE_EXTENSIONS = {
        ".php", ".asp", ".aspx", ".cgi", ".jsp", ".exe", ".scr", ".bat", ".cmd",
    }
    
    CLEAN_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar", ".txt"
    }
    
class TLDConfig:
    HIGH_RISK_TLDS = {
        "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "buzz", "work", "support", "monster", "rest",
    }
    MEDIUM_RISK_TLDS = {
        "info", "biz", "online", "site", "website", "live", "shop", "store",
    }
    LOW_RISK_TLDS = {
        "com", "net", "org", "edu", "gov", "mil",
    }
    COUNTRY_CODE_TLDS = {
        "vn", "com.vn", "co.uk", "uk", "jp", "de", "fr",
    }

    HIGH_RISK_SCORE = 80
    MEDIUM_RISK_SCORE = 40
    LOW_RISK_SCORE = 0
    COUNTRY_SCORE = 10
    UNKNOWN_SCORE = 20
    
class TyposquattingConfig:
    MAX_LEVENSHTEIN_DISTANCE = 3
    
    # LỖI 1 FIX: Hạ ngưỡng tương đồng từ 0.80 xuống 0.60 
    # Để bắt được các brand ngắn bị đổi từ 2 ký tự trở lên (như g00gle)
    MIN_SIMILARITY_SCORE = 0.60

    BRAND_DOMAINS = {
        "vietcombank": "vietcombank.com.vn",
        "techcombank": "techcombank.com.vn",
        "vpbank": "vpbank.com.vn",
        "momo": "momo.vn",
        "zalopay": "zalopay.vn",
        "grab": "grab.com",
        "shopee": "shopee.vn",
        "paypal": "paypal.com",
        "google": "google.com",
        "netflix": "netflix.com",
    }
    
    SUSPICIOUS_CHARS  = {"а", "е", "о", "р", "с", "х", "і", "ј"}
    
class RiskConfig:
    # Brand
    BRAND_IN_SUBDOMAIN_WEIGHT = 25
    BRAND_IN_PATH_WEIGHT = 15

    # Typosquatting
    TYPOSQUATTING_WEIGHT = 35
    HOMOGLYPH_WEIGHT = 40

    SUSPICIOUS_KEYWORD_WEIGHT = 8
    MAX_KEYWORD_SCORE = 45        

    # Pattern
    ENCODED_CHARACTER_WEIGHT = 8
    DOUBLE_EXTENSION_WEIGHT = 30
    SUSPICIOUS_EXTENSION_WEIGHT = 25
    URL_SHORTENER_WEIGHT = 15
    IP_URL_WEIGHT = 20

    # TLD
    HIGH_RISK_TLD_WEIGHT = 15
    MEDIUM_RISK_TLD_WEIGHT = 8

    # Lexical Thresholds
    LONG_URL_THRESHOLD = 75
    ENTROPY_THRESHOLD = 4.0
    DIGIT_RATIO_THRESHOLD = 0.30
    SUBDOMAIN_THRESHOLD = 3

    # Lexical Weights - LỖI 3 FIX: Tăng một chút sức nặng cho độ dài URL hình tháp
    LONG_URL_WEIGHT = 12           # Tăng từ 8 lên 12 điểm
    HIGH_ENTROPY_WEIGHT = 10
    DIGIT_RATIO_WEIGHT = 10        # Tăng từ 8 lên 10 điểm (Giúp phạt g00gle nặng hơn)
    SUBDOMAIN_WEIGHT = 10
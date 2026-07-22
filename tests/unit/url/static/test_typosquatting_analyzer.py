import pytest
from src.core.models import ValidationResult, URLComponents, TyposquattingAnalysis
from src.analyzers.url.static.typosquatting_analyzer import TyposquattingAnalyzer
from src.analyzers.url.static.config import TyposquattingConfig

@pytest.fixture
def analyzer():
    return TyposquattingAnalyzer()


@pytest.fixture(autouse=True)
def mock_typo_config(monkeypatch):
    """Cô lập môi trường test bằng việc ghim cứng dữ liệu mẫu config."""
    monkeypatch.setattr(TyposquattingConfig, "MAX_LEVENSHTEIN_DISTANCE", 3)
    monkeypatch.setattr(TyposquattingConfig, "MIN_SIMILARITY_SCORE", 0.80)
    monkeypatch.setattr(TyposquattingConfig, "BRAND_DOMAINS", {
        "vietcombank": "vietcombank.com.vn",
        "google": "google.com"
    })
    monkeypatch.setattr(TyposquattingConfig, "SUSPICIOUS_CHARS", {"а", "е"}) # Ký tự đặc biệt Cyrillic


# --- 1. DEFENSIVE TEST ---
def test_missing_components_raise_error(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(ValidationResult(valid=False, components=None))


# --- 2. POSITIVE DETECTIONS (TYPO & HOMOGLYPH) ---
def test_detect_keyboard_typo(analyzer):
    """Kiểm tra phát hiện lỗi gõ nhầm kí tự liền kề."""
    components = URLComponents(
        scheme="https", subdomain="", domain="vietcomhank", tld="com",
        full_domain="vietcomhank.com", path="", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.suspicious is True
    assert result.target_brand == "vietcombank"
    assert result.target_domain == "vietcombank.com.vn"
    assert result.keyboard_typo_detected is True
    assert result.homoglyph_detected is False


def test_detect_homoglyph_attack(analyzer):
    """Đảm bảo đòn tấn công Homoglyph không bị lọt lưới qua bộ lọc SequenceMatcher."""
    components = URLComponents(
        scheme="https", subdomain="", domain="vietcombаnk", tld="net",
        full_domain="vietcombаnk.net", path="", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.suspicious is True
    assert result.homoglyph_detected is True


# --- 3. NEGATIVE TESTS (FALSE POSITIVE MANAGEMENT) ---
def test_exact_brand_match_negative(analyzer):
    """
    TEST ĐÁNH GIÁ CHẤT LƯỢNG: Trang chính chủ thật sự của thương hiệu 
    KHÔNG ĐƯỢC PHÉP dính cờ suspicious bừa bãi.
    """
    components = URLComponents(
        scheme="https", subdomain="www", domain="vietcombank", tld="com.vn",
        full_domain="vietcombank.com.vn", path="/index.html", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.suspicious is False
    assert result.target_brand is None


def test_similarity_score_under_threshold(analyzer):
    """Đảm bảo domain có khoảng cách gần nhưng độ tương đồng thực tế quá thấp không kích hoạt báo động rác."""
    components = URLComponents(
        scheme="https", subdomain="", domain="vietnamesebank", tld="com",
        full_domain="vietnamesebank.com", path="", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.suspicious is False


def test_clean_url(analyzer):
    """95% Use-case: Đảm bảo kiểm tra các trang sạch thông thường không gây nhiễu signal."""
    components = URLComponents(
        scheme="https", subdomain="www", domain="google", tld="com",
        full_domain="google.com", path="/", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.suspicious is False
    assert result.similarity_score == 0.0
    assert result.homoglyph_detected is False
    
def test_legitimate_subdomain_not_suspicious(analyzer):
    components = URLComponents(
        scheme="https",
        subdomain="secure.www",
        domain="google",
        tld="com",
        full_domain="secure.www.google.com",
        path="/login",
        params={}
    )

    result = analyzer.analyze(
        ValidationResult(
            valid=True,
            components=components
        )
    )

    assert result.suspicious is False
    
def test_distance_too_large(analyzer):
    components = URLComponents(
        scheme="https",
        subdomain="",
        domain="vietcompletelydifferent",
        tld="com",
        full_domain="vietcompletelydifferent.com",
        path="",
        params={}
    )

    result = analyzer.analyze(
        ValidationResult(
            valid=True,
            components=components
        )
    )

    assert result.suspicious is False
    
def test_empty_domain(analyzer):
    components = URLComponents(
        scheme="https",
        subdomain="",
        domain="",
        tld="com",
        full_domain="",
        path="",
        params={}
    )

    result = analyzer.analyze(
        ValidationResult(
            valid=True,
            components=components
        )
    )

    assert result.suspicious is False
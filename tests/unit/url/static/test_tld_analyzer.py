import pytest
from src.core.models import ValidationResult, URLComponents, TLDAnalysis
from src.analyzers.url.static.tld_analyzer import TLDAnalyzer
from src.analyzers.url.static.config import TLDConfig

@pytest.fixture
def analyzer():
    """Fixture khởi tạo TLDAnalyzer."""
    return TLDAnalyzer()


@pytest.fixture(autouse=True)
def mock_tld_config(monkeypatch):
    """Stubbing cấu hình TLDConfig để tạo môi trường test cô lập."""
    monkeypatch.setattr(TLDConfig, "HIGH_RISK_TLDS", {"xyz", "tk"})
    monkeypatch.setattr(TLDConfig, "MEDIUM_RISK_TLDS", {"info"})
    monkeypatch.setattr(TLDConfig, "LOW_RISK_TLDS", {"com"})
    monkeypatch.setattr(TLDConfig, "COUNTRY_CODE_TLDS", {"vn", "tk"})

    monkeypatch.setattr(TLDConfig, "HIGH_RISK_SCORE", 80)
    monkeypatch.setattr(TLDConfig, "MEDIUM_RISK_SCORE", 40)
    monkeypatch.setattr(TLDConfig, "LOW_RISK_SCORE", 0)
    monkeypatch.setattr(TLDConfig, "COUNTRY_SCORE", 10)
    monkeypatch.setattr(TLDConfig, "UNKNOWN_SCORE", 20)


# --- 1. DEFENSIVE & INPUT SANITIZATION TESTS ---
def test_missing_components_raise_error(analyzer):
    """Business rule: Thiếu components bắt buộc phải quăng lỗi ValueError."""
    with pytest.raises(ValueError) as exc_info:
        analyzer.analyze(ValidationResult(valid=False, components=None))
    assert "ValidationResult must contain URL components." in str(exc_info.value)


def test_tld_strip_whitespace(analyzer):
    """Kiểm tra khả năng tự động gọt bỏ khoảng trắng thừa ở hai đầu TLD."""
    components = URLComponents(
        scheme="https", subdomain="", domain="evil", tld=" xyz ",
        full_domain="evil.xyz", path="", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.tld == "xyz"
    assert result.risk_level == "high"


def test_empty_tld(analyzer):
    """Kiểm tra Edge Case với TLD rỗng (ví dụ tên miền nội bộ localhost hoặc IP address)."""
    components = URLComponents(
        scheme="https", subdomain="", domain="localhost", tld="",
        full_domain="localhost", path="", params={}
    )
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.tld == ""
    assert result.risk_level == "unknown"
    assert result.risk_score == TLDConfig.UNKNOWN_SCORE


# --- 2. RISK LEVEL TESTS ---
def test_high_risk_tld(analyzer):
    """Kiểm tra phân lớp rủi ro cao."""
    components = URLComponents(scheme="https", subdomain="", domain="scam", tld="xyz", full_domain="scam.xyz", path="", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.tld == "xyz"
    assert result.risk_level == "high"
    assert result.risk_score == 80
    assert result.high_risk_tld is True


def test_medium_risk_tld(analyzer):
    """Kiểm tra phân lớp rủi ro trung bình."""
    components = URLComponents(scheme="https", subdomain="", domain="deal", tld="info", full_domain="deal.info", path="", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.risk_level == "medium"
    assert result.risk_score == 40
    assert result.medium_risk_tld is True


def test_country_code_tld(analyzer):
    """Kiểm tra tên miền quốc gia thuần túy không thuộc nhóm nguy hại (e.g. .vn)."""
    components = URLComponents(scheme="https", subdomain="", domain="company", tld="vn", full_domain="company.vn", path="", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.risk_level == "country"
    assert result.risk_score == 10
    assert result.country_code_tld is True


# --- 3. LOGIC & INTEGRITY TESTS ---
def test_overlap_high_risk_and_country_code(analyzer):
    """
    Test cực kỳ quan trọng: Chứng minh Overlap Bug đã được sửa.
    Với '.tk', nhãn rủi ro ưu tiên là 'high', nhưng cờ 'country_code_tld' VẪN phải là True.
    """
    components = URLComponents(scheme="http", subdomain="", domain="malicious", tld="tk", full_domain="malicious.tk", path="", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.risk_level == "high"
    assert result.risk_score == 80
    assert result.high_risk_tld is True
    assert result.country_code_tld is True


def test_unknown_tld_fallback(analyzer):
    """Chốt chặn an toàn: TLD lạ hoắc không nằm trong config (e.g. .space)."""
    components = URLComponents(scheme="https", subdomain="", domain="mystery", tld="space", full_domain="mystery.space", path="", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.risk_level == "unknown"
    assert result.risk_score == 20
    assert result.high_risk_tld is False
    assert result.country_code_tld is False


def test_clean_url(analyzer):
    """Sanity Test (95% ngoài đời): Đảm bảo tên miền sạch quốc dân không sinh tín hiệu rác."""
    components = URLComponents(scheme="https", subdomain="www", domain="google", tld="com", full_domain="www.google.com", path="/", params={})
    result = analyzer.analyze(ValidationResult(valid=True, components=components))

    assert result.risk_level == "low"
    assert result.risk_score == 0
    assert result.low_risk_tld is True
    assert result.high_risk_tld is False
    assert result.medium_risk_tld is False
    assert result.country_code_tld is False
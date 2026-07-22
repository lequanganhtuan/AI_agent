import pytest
from src.core.models import ValidationResult, URLComponents, PatternAnalysis, URLMetadata
from src.analyzers.url.static.pattern_analyzer import PatternAnalyzer
from src.analyzers.url.static.config import PatternConfig

# Mock metadata cho kịch bản IP Address URL
class MockMetadata:
    def __init__(self, is_ip: bool):
        self.is_ip = is_ip


@pytest.fixture
def analyzer():
    """Fixture khởi tạo PatternAnalyzer sạch cho mỗi test case."""
    return PatternAnalyzer()


@pytest.fixture(autouse=True)
def mock_pattern_config(monkeypatch):
    """Đóng băng dữ liệu Config mẫu cố định phục vụ kiểm thử độc lập."""
    monkeypatch.setattr(PatternConfig, "SUSPICIOUS_KEYWORDS", {"login", "verify", "secure"})
    monkeypatch.setattr(PatternConfig, "URL_SHORTENERS", {"bit.ly", "tinyurl.com"})
    monkeypatch.setattr(PatternConfig, "SUSPICIOUS_FILE_EXTENSIONS", {".exe", ".bat"})
    monkeypatch.setattr(PatternConfig, "CLEAN_EXTENSIONS", {".pdf", ".zip", ".doc"})


# --- 1. BUSINESS RULE TEST ---
def test_missing_components_raise_error(analyzer):
    """Kiểm tra chốt chặn dữ liệu khuyết thiếu bắt buộc phải văng ValueError."""
    with pytest.raises(ValueError) as exc_info:
        analyzer.analyze(ValidationResult(valid=False, components=None))
    assert "ValidationResult must contain URL components." in str(exc_info.value)


# --- 2. KEYWORD TESTS ---
def test_detect_keywords(analyzer):
    """Kiểm tra khả năng phát hiện chính xác từ khóa bẩn sau khi bóc tách."""
    components = URLComponents(
        scheme="https", subdomain="", domain="scam-site", tld="com",
        full_domain="scam-site.com", path="/verify/login-page", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://scam-site.com/verify/login-page", components=components)
    result = analyzer.analyze(res)

    assert result.suspicious_keyword_count == 2
    assert result.suspicious_keywords == ["login", "verify"]


def test_keyword_false_positive(analyzer):
    """
    Test cực kỳ quan trọng: Chứng minh Tokenization hoạt động đúng.
    Từ khóa 'secure' nằm trong chuỗi 'insecure-page' KHÔNG ĐƯỢC PHÉP tách riêng ra.
    """
    components = URLComponents(
        scheme="https", subdomain="", domain="abc", tld="com",
        full_domain="abc.com", path="/insecure-page", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://abc.com/insecure-page", components=components)
    result = analyzer.analyze(res)

    assert result.suspicious_keywords == []
    assert result.suspicious_keyword_count == 0


# --- 3. ENCODED CHARACTER TESTS ---
def test_encoded_character(analyzer):
    """Kiểm tra nhận diện 1 ký tự mã hóa URL (khoảng trắng %20)."""
    components = URLComponents(
        scheme="https", subdomain="", domain="abc", tld="com",
        full_domain="abc.com", path="/login%20verify", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://abc.com/login%20verify", components=components)
    result = analyzer.analyze(res)

    assert result.encoded_character_detected is True
    assert result.encoded_character_count == 1


def test_multiple_encoded_characters(analyzer):
    """Kiểm tra đếm chính xác nhiều ký tự mã hóa URL băm nhỏ liên tiếp."""
    components = URLComponents(
        scheme="https", subdomain="", domain="abc", tld="com",
        full_domain="abc.com", path="/%20%2f%3d", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://abc.com/%20%2f%3d", components=components)
    result = analyzer.analyze(res)

    assert result.encoded_character_detected is True
    assert result.encoded_character_count == 3


# --- 4. EXTENSION TESTS ---
def test_double_extension(analyzer):
    """Phát hiện chiêu trò đổi đuôi file nguy hiểm giả lập tài liệu (e.g., .pdf.exe)."""
    components = URLComponents(
        scheme="https", subdomain="", domain="safe-download", tld="org",
        full_domain="safe-download.org", path="/docs/report.pdf.exe", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://safe-download.org/docs/report.pdf.exe", components=components)
    result = analyzer.analyze(res)

    assert result.double_extension_detected is True


def test_double_extension_negative(analyzer):
    """Đảm bảo URL tải file tài liệu thông thường (.pdf) không bị nhận nhầm là double extension."""
    components = URLComponents(
        scheme="https", subdomain="", domain="abc", tld="com",
        full_domain="abc.com", path="/report.pdf", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://abc.com/report.pdf", components=components)
    result = analyzer.analyze(res)

    assert result.double_extension_detected is False


def test_suspicious_extension(analyzer):
    """Kiểm tra nhận diện đuôi file thực thi nguy hại (.exe)."""
    components = URLComponents(
        scheme="https", subdomain="", domain="abc", tld="com",
        full_domain="abc.com", path="/update.exe", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://abc.com/update.exe", components=components)
    result = analyzer.analyze(res)

    assert result.suspicious_file_extension is True


# --- 5. INFRASTRUCTURE TESTS ---
def test_ip_address_url(analyzer):
    """Kiểm tra khả năng bóc trích signal IP từ đối tượng metadata chuẩn."""
    components = URLComponents(
        scheme="http", subdomain="", domain="192.168.1.1", tld="",
        full_domain="192.168.1.1", path="", params={}
    )
    
    # Sử dụng URLMetadata thật của hệ thống để Pydantic validate thành công
    res = ValidationResult(
        valid=True, 
        normalized_url="http://192.168.1.1", 
        components=components,
        metadata=URLMetadata(is_ip=True) # <-- Sửa ở đây
    )
    result = analyzer.analyze(res)

    assert result.ip_address_url is True


def test_url_shortener(analyzer):
    """Phát hiện dịch vụ rút gọn liên kết nằm trong danh sách theo dõi."""
    components = URLComponents(
        scheme="https", subdomain="", domain="tinyurl", tld="com",
        full_domain="tinyurl.com", path="/shortlink", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://tinyurl.com/shortlink", components=components)
    result = analyzer.analyze(res)

    assert result.url_shortener_detected is True


# --- 6. INTEGRITY & SANITY TEST (95% USE-CASE) ---
def test_clean_url(analyzer):
    """
    Test sống còn: Đảm bảo URL sạch tuyệt đối không sinh ra bất kỳ signal bẩn nào.
    Mọi trường thuộc tính kiểm thử bắt buộc phải trả về False, rỗng hoặc 0.
    """
    components = URLComponents(
        scheme="https", subdomain="www", domain="google", tld="com",
        full_domain="www.google.com", path="/", params={}
    )
    res = ValidationResult(valid=True, normalized_url="https://www.google.com/", components=components)
    result = analyzer.analyze(res)

    # Khẳng định toàn bộ cấu trúc dữ liệu trả về ở trạng thái "sạch"
    assert result.suspicious_keywords == []
    assert result.suspicious_keyword_count == 0
    assert result.encoded_character_detected is False
    assert result.encoded_character_count == 0
    assert result.double_extension_detected is False
    assert result.suspicious_file_extension is False
    assert result.ip_address_url is False
    assert result.url_shortener_detected is False
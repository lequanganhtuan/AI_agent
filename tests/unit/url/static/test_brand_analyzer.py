import pytest
from src.core.models import ValidationResult, URLComponents, BrandAnalysis
from src.analyzers.url.static.brand_analyzer import BrandAnalyzer
from src.analyzers.url.static.config import BrandConfig

@pytest.fixture
def brand_analyzer():
    """Fixture cung cấp instance sạch của BrandAnalyzer."""
    return BrandAnalyzer()


@pytest.fixture(autouse=True)
def mock_brand_config(monkeypatch):
    """
    Stubbing/Mocking cấu hình BrandConfig nội bộ.
    Lưu ý: Danh sách trắng chỉ lưu tên miền gốc để test cơ chế endswith() mới.
    """
    test_keywords = ["Paypal", "Google", "Netflix"]
    test_legitimate = {
        "paypal": {"paypal.com"},  # Không cần khai báo www, hệ thống mới tự xử lý được
        "google": {"google.com"},
        "netflix": {"netflix.com"}
    }
    monkeypatch.setattr(BrandConfig, "BRAND_KEYWORDS", test_keywords)
    monkeypatch.setattr(BrandConfig, "LEGITIMATE_DOMAINS", test_legitimate)


def test_analyze_missing_components_raises_value_error(brand_analyzer):
    """Case 1: Kiểm tra chốt chặn bảo vệ đầu vào khi khuyết thiếu components."""
    invalid_result = ValidationResult(valid=False, normalized_url=None, components=None)
    
    with pytest.raises(ValueError) as exc_info:
        brand_analyzer.analyze(invalid_result)
    assert "ValidationResult must contain URL components." in str(exc_info.value)


def test_analyze_no_brand_detected(brand_analyzer, mock_brand_config):
    """Case 2: URL sạch, không chứa bất kỳ thương hiệu nào bị theo dõi."""
    components = URLComponents(
        scheme="https", subdomain="", domain="unknown-shop", tld="net",
        full_domain="unknown-shop.net", path="/products/item-1", params={}
    )
    result = brand_analyzer.analyze(ValidationResult(valid=True, normalized_url="https://unknown-shop.net/products/item-1", components=components))

    assert result.detected_brand is None
    assert result.brand_in_subdomain is False
    assert result.brand_in_path is False
    assert result.legitimate_domain_match is False


def test_analyze_legitimate_subdomain_match(brand_analyzer, mock_brand_config):
    """
    Case 3: QUAN TRỌNG - Test tính năng mới của code sửa đổi.
    URL chứa subdomain chính chủ (www.paypal.com hoặc secure.paypal.com).
    Hệ thống phải tự nhận diện được đuôi .paypal.com hợp pháp thông qua logic endswith.
    """
    components = URLComponents(
        scheme="https", subdomain="secure.www", domain="paypal", tld="com",
        full_domain="secure.www.paypal.com", path="/signin", params={}
    )
    result = brand_analyzer.analyze(ValidationResult(valid=True, normalized_url="https://secure.www.paypal.com/signin", components=components))

    assert result.detected_brand == "paypal"
    assert result.legitimate_domain_match is True  # Đã Pass nhờ cơ chế check đuôi thông minh mới
    assert result.brand_in_subdomain is False      # Từ khóa nằm ở phần root chứ không phải mạo danh ở tầng subdomain bẫy


def test_analyze_phishing_brand_in_subdomain(brand_analyzer, mock_brand_config):
    """Case 4: Kịch bản Phishing - Hacker gài chữ paypal thành một phần của subdomain bẫy."""
    components = URLComponents(
        scheme="https", subdomain="paypal.com.security-update", domain="attacker-site", tld="xyz",
        full_domain="paypal.com.security-update.attacker-site.xyz", path="/login", params={}
    )
    result = brand_analyzer.analyze(ValidationResult(valid=True, normalized_url="https://paypal.com.security-update.attacker-site.xyz/login", components=components))

    assert result.detected_brand == "paypal"
    assert result.brand_in_subdomain is True
    assert result.legitimate_domain_match is False # Kênh mạo danh, không khớp danh sách trắng


def test_analyze_phishing_brand_in_path(brand_analyzer, mock_brand_config):
    """Case 5: Kịch bản Phishing - Hacker nhét tên thương hiệu vào sâu trong đường dẫn (Path)."""
    components = URLComponents(
        scheme="http", subdomain="", domain="scam-server", tld="click",
        full_domain="scam-server.click", path="/web/netflix/account-recovery", params={}
    )
    result = brand_analyzer.analyze(ValidationResult(valid=True, normalized_url="http://scam-server.click/web/netflix/account-recovery", components=components))

    assert result.detected_brand == "netflix"
    assert result.brand_in_path is True
    assert result.legitimate_domain_match is False


def test_analyze_case_insensitivity(brand_analyzer, mock_brand_config):
    """Case 6: Đảm bảo bộ phân tích ép dữ liệu về chữ thường (lowercase) để xử lý không lệch pha."""
    components = URLComponents(
        scheme="https", subdomain="PAYPAL", domain="scam-portal", tld="com",
        full_domain="PAYPAL.scam-portal.com", path="/GoOgLe/login", params={}
    )
    result = brand_analyzer.analyze(ValidationResult(valid=True, normalized_url="https://PAYPAL.scam-portal.com/GoOgLe/login", components=components))

    # Hệ thống mới trả về chữ thường hoàn toàn
    assert result.detected_brand == "paypal"
    assert result.brand_in_subdomain is True
    assert result.legitimate_domain_match is False
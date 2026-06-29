import pytest
from src.core.models import ValidationResult, URLComponents, LexicalFeatures
from src.analyzers.url.static.lexical_analyzer import LexicalAnalyzer

@pytest.fixture
def lexical_analyzer():
    """Fixture khởi tạo LexicalAnalyzer cho các test case."""
    return LexicalAnalyzer()


def test_analyze_success_flow(lexical_analyzer):
    """
    Case 1: Test luồng phân tích thành công tổng thể (Đã sửa comment sai).
    URL: https://sub.my-bank77.com/login/secure?session=123&user=test
    """
    components = URLComponents(
        scheme="https",
        subdomain="sub",
        domain="my-bank77",
        tld="com",
        full_domain="sub.my-bank77.com",
        path="/login/secure",
        params={"session": "123", "user": "test"}
    )
    validation_result = ValidationResult(
        valid=True,
        normalized_url="https://sub.my-bank77.com/login/secure?session=123&user=test",
        components=components
    )

    features = lexical_analyzer.analyze(validation_result)

    assert isinstance(features, LexicalFeatures)
    assert features.url_length == len(validation_result.normalized_url)
    assert features.root_domain_length == len("my-bank77")      # 9
    assert features.full_domain_length == len("sub.my-bank77.com") # 17 (Đã sửa comment)
    assert features.subdomain_count == 1
    assert features.query_parameter_count == 2
    assert features.url_depth == 2
    assert features.max_path_segment_length == 6                # len('secure') = 6


def test_digit_ratio_approximate(lexical_analyzer):
    """Case 2: Test tỷ lệ số sử dụng pytest.approx để tránh vỡ test khi đổi độ chia thập phân."""
    components = URLComponents(
        scheme="http", subdomain="", domain="bank123456", tld="com",
        full_domain="bank123456.com", path="", params={}
    )
    validation_result = ValidationResult(valid=True, normalized_url="http://bank123456.com", components=components)
    features = lexical_analyzer.analyze(validation_result)

    # Sử dụng chuẩn Enterprise: approx với sai số abs=1e-4
    assert features.digit_ratio_domain == pytest.approx(0.4286, abs=1e-4)


def test_high_entropy_greater_than_normal_domain(lexical_analyzer):
    """Case 3: Test Entropy động. Tên miền ngẫu nhiên PHẢI có entropy lớn hơn tên miền tự nhiên."""
    # 1. Tên miền tự nhiên (Google)
    res_google = ValidationResult(
        valid=True, normalized_url="https://google.com",
        components=URLComponents(scheme="https", subdomain="", domain="google", tld="com", full_domain="google.com", path="", params={})
    )
    # 2. Tên miền DGA băm ngẫu nhiên của Hacker
    res_dga = ValidationResult(
        valid=True, normalized_url="https://a8s9df8as7df98a7sd.com",
        components=URLComponents(scheme="https", subdomain="", domain="a8s9df8as7df98a7sd", tld="com", full_domain="a8s9df8as7df98a7sd.com", path="", params={})
    )

    entropy_google = lexical_analyzer.analyze(res_google).domain_entropy
    entropy_dga = lexical_analyzer.analyze(res_dga).domain_entropy

    # Khẳng định có giá trị: Tránh việc hàm luôn hardcode return 1.0
    assert entropy_dga > entropy_google


def test_deep_subdomain_count(lexical_analyzer):
    """Case 4: Test đếm subdomain sâu (Đặc trưng của Phishing URL)."""
    components = URLComponents(
        scheme="https", subdomain="secure.login.verify", domain="bank", tld="com",
        full_domain="secure.login.verify.bank.com", path="", params={}
    )
    validation_result = ValidationResult(valid=True, normalized_url="https://secure.login.verify.bank.com", components=components)
    features = lexical_analyzer.analyze(validation_result)

    assert features.subdomain_count == 3  # 'secure', 'login', 'verify'


def test_deep_path_depth(lexical_analyzer):
    """Case 5: Test độ sâu path lớn để tránh bug thuật toán split."""
    components = URLComponents(
        scheme="https", subdomain="", domain="google", tld="com", full_domain="google.com",
        path="/1/2/3/4/5", params={}
    )
    validation_result = ValidationResult(valid=True, normalized_url="https://google.com/1/2/3/4/5", components=components)
    features = lexical_analyzer.analyze(validation_result)

    assert features.url_depth == 5
    assert features.max_path_segment_length == 1


def test_exact_special_char_count(lexical_analyzer):
    """
    Case 6: Test đếm chính xác ký tự đặc biệt.
    Giả định StaticConfig.SPECIAL_CHARS chứa {'?', '=', '&'}
    URL: https://google.com/login?token=1&id=2 -> Có 1 dấu '?', 2 dấu '=', 1 dấu '&' -> Tổng 4
    """
    # Ép cấu hình SPECIAL_CHARS cố định trong môi trường test để đảm bảo deterministic
    lexical_analyzer.SPECIAL_CHARS = {"?", "=", "&"}
    
    components = URLComponents(
        scheme="https", subdomain="", domain="google", tld="com", full_domain="google.com",
        path="/login", params={"token": "1", "id": "2"}
    )
    validation_result = ValidationResult(
        valid=True, normalized_url="https://google.com/login?token=1&id=2", components=components
    )
    features = lexical_analyzer.analyze(validation_result)

    assert features.url_special_char_count == 4


def test_edge_case_empty_domain(lexical_analyzer):
    """Case 7: Test Edge Case khi full_domain trống (Xử lý phòng thủ của hàm tĩnh)."""
    components = URLComponents(
        scheme="https", subdomain="", domain="", tld="", full_domain="", path="", params={}
    )
    validation_result = ValidationResult(valid=True, normalized_url="https://", components=components)
    features = lexical_analyzer.analyze(validation_result)

    assert features.root_domain_length == 0
    assert features.full_domain_length == 0
    assert features.digit_ratio_domain == 0.0
    assert features.domain_entropy == 0.0
    assert features.longest_token_length == 0


def test_edge_case_empty_path(lexical_analyzer):
    """Case 8: Test Edge Case khi path trống."""
    components = URLComponents(
        scheme="https", subdomain="", domain="google", tld="com", full_domain="google.com", path="", params={}
    )
    validation_result = ValidationResult(valid=True, normalized_url="https://google.com", components=components)
    features = lexical_analyzer.analyze(validation_result)

    assert features.url_depth == 0
    assert features.max_path_segment_length == 0


def test_analyze_missing_components_raise_error(lexical_analyzer):
    """Case 9: Bảo vệ nghiêm ngặt Business Rule phòng thủ dữ liệu Khuyết/Rỗng."""
    invalid_result = ValidationResult(valid=False, normalized_url=None, components=None)

    with pytest.raises(ValueError) as exc_info:
        lexical_analyzer.analyze(invalid_result)
        
    assert "ValidationResult must contain normalized_url and components." in str(exc_info.value)


def test_phishing_like_domain_features(lexical_analyzer):
    """Case 10: Test tích hợp dữ liệu Production - Mô phỏng Phishing URL thực tế."""
    components = URLComponents(
        scheme="https", subdomain="", domain="secure-paypal-login-update-2026", tld="xyz",
        full_domain="secure-paypal-login-update-2026.xyz", path="", params={}
    )
    validation_result = ValidationResult(
        valid=True, normalized_url="https://secure-paypal-login-update-2026.xyz", components=components
    )
    features = lexical_analyzer.analyze(validation_result)

    # Kiểm thử bộ nhận diện hành vi nguy cơ cao
    assert features.hyphen_count == 4                # 4 dấu '-'
    assert features.consecutive_digit_count == 4     # Chuỗi '2026' -> 4 số liên tiếp
    assert features.longest_token_length > 5         # 'paypal', 'secure', 'update' đều > 5
    assert features.domain_entropy > 3.0             # Chuỗi hỗn hợp chữ-số-gạch-ngang bắt buộc phải có entropy cao
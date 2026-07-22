import pytest
from src.core.models import (
    LexicalFeatures, BrandAnalysis, PatternAnalysis, 
    TLDAnalysis, TyposquattingAnalysis, StaticRiskAnalysis
)
from src.analyzers.url.static.static_risk_calculator import StaticRiskCalculator
from src.analyzers.url.static.config import RiskConfig

@pytest.fixture
def calculator():
    """Fixture khởi tạo bộ tính toán rủi ro tĩnh."""
    return StaticRiskCalculator()


@pytest.fixture
def mock_clean_inputs():
    """
    Fixture tạo nhanh tuple object dữ liệu sạch làm nền tảng đầu vào.
    Sử dụng model_construct() để bypass tầng validation nghiêm ngặt của Pydantic.
    """
    lexical_mock = LexicalFeatures.model_construct(
        url_length=20, 
        domain_entropy=2.1, 
        digit_ratio_domain=0.0, 
        subdomain_count=1
    )
    
    brand_mock = BrandAnalysis.model_construct(
        detected_brand=None, 
        brand_in_subdomain=False, 
        brand_in_path=False, 
        legitimate_domain_match=False
    )
    
    pattern_mock = PatternAnalysis.model_construct(
        suspicious_keyword_count=0, 
        suspicious_keywords=[], 
        encoded_character_detected=False, 
        double_extension_detected=False, 
        suspicious_file_extension=False, 
        url_shortener_detected=False, 
        ip_address_url=False
    )
    
    tld_mock = TLDAnalysis.model_construct(
        tld="com", 
        high_risk_tld=False, 
        medium_risk_tld=False
    )
    
    typo_mock = TyposquattingAnalysis.model_construct(
        suspicious=False, 
        target_domain=None, 
        homoglyph_detected=False
    )
    
    return (lexical_mock, brand_mock, pattern_mock, tld_mock, typo_mock)


def test_clean_url_yields_zero_score(calculator, mock_clean_inputs):
    """Đảm bảo URL sạch đạt điểm 0 tuyệt đối và không phát sinh log rác."""
    lex, brand, pat, tld, typo = mock_clean_inputs
    result = calculator.calculate(lex, brand, pat, tld, typo)
    
    assert result.score == 0
    assert result.risk_level == "low"
    assert result.triggered_signals == []


def test_digit_ratio_threshold_match(calculator, mock_clean_inputs):
    """Kiểm tra việc kích hoạt cờ và cộng điểm khi tỷ lệ chữ số vượt ngưỡng."""
    lex, brand, pat, tld, typo = mock_clean_inputs
    # Cấu hình ngưỡng DIGIT_RATIO_THRESHOLD = 0.30, ta đặt 0.35 để kích hoạt
    lex.digit_ratio_domain = 0.35 
    
    result = calculator.calculate(lex, brand, pat, tld, typo)
    
    assert "high_digit_ratio" in result.triggered_signals  # Đã khớp theo code của bạn
    assert result.score == RiskConfig.DIGIT_RATIO_WEIGHT


def test_brand_in_subdomain_scoring_and_logging(calculator, mock_clean_inputs):
    """Kiểm tra việc tính toán điểm và log chuẩn xác khi brand lọt vào subdomain."""
    lex, brand, pat, tld, typo = mock_clean_inputs
    brand.detected_brand = "paypal"
    brand.brand_in_subdomain = True
    brand.legitimate_domain_match = False
    
    result = calculator.calculate(lex, brand, pat, tld, typo)
    
    assert "brand_impersonation_subdomain" in result.triggered_signals
    assert "URL subdomain" in result.summary[0]
    assert result.score == RiskConfig.BRAND_IN_SUBDOMAIN_WEIGHT


def test_score_saturation_max_limit_100(calculator, mock_clean_inputs):
    """Đảm bảo điểm rủi ro tổng kết không bao giờ vượt qua ngưỡng trần 100 điểm."""
    lex, brand, pat, tld, typo = mock_clean_inputs
    
    # Gán đồng thời nhiều thuộc tính độc hại để vượt 100 điểm lý thuyết
    pat.double_extension_detected = True       # +30đ
    pat.suspicious_file_extension = True     # +25đ
    typo.suspicious = True                     # +35đ
    tld.high_risk_tld = True                   # +15đ
    # Tổng lý thuyết: 30 + 25 + 35 + 15 = 105đ -> Kết quả phải ép về 100
    
    result = calculator.calculate(lex, brand, pat, tld, typo)
    
    assert result.score == 100
    assert result.risk_level == "high"
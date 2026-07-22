import pytest
from src.core.enums import ValidationErrorCode
from src.core.exceptions import URLValidationException
from src.analyzers.url.preprocessing.validator import URLValidator

@pytest.fixture
def validator():
    """Fixture provides an instance of URLValidator for each test case."""
    return URLValidator()


def test_validate_valid_url(validator):
    """Case 1: Valid URL does not raise exception."""
    url = "https://google.com"
    try:
        validator.validate(url)
    except URLValidationException:
        pytest.fail("Valid URL but raised URLValidationException")


def test_validate_invalid_scheme(validator):
    """Case 2: Invalid scheme (ftp://)"""
    url= "ftp://google.com"
    with pytest.raises(URLValidationException) as exc_info:
        validator.validate(url)
    
    assert exc_info.value.code == ValidationErrorCode.INVALID_SCHEME


def test_validate_invalid_url_format(validator):
    """Case 3: URL format is completely wrong."""
    url = "not-a-url"
    with pytest.raises(URLValidationException) as exc_info:
        validator.validate(url)
    
    assert exc_info.value.code == ValidationErrorCode.INVALID_URL_FORMAT


def test_validate_url_too_long(validator):
    """Case 4: URL is too long (exceeds default config 2048 characters)."""
    url = "https://google.com/" + ("a" * 3000)
    with pytest.raises(URLValidationException) as exc_info:
        validator.validate(url)
    
    assert exc_info.value.code == ValidationErrorCode.URL_TOO_LONG


def test_validate_allowed_internal_ips(validator):
    """Case 5: Internal/private/loopback IPs are allowed and do not raise exception."""
    urls = [
        "http://169.254.169.254",
        "http://127.0.0.1",
        "http://192.168.1.10"
    ]
    for url in urls:
        try:
            validator.validate(url)
        except URLValidationException:
            pytest.fail(f"SSRF URL {url} raised URLValidationException but should be allowed")
import pytest
from src.core.enums import ValidationErrorCode
from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer

@pytest.fixture
def analyzer():
    """Fixture provides an initialized instance of the URLAnalyzer coordinator."""
    return URLAnalyzer()


def test_analyzer_end_to_end_success(analyzer):
    """
    Case 1: End-to-End Success.
    Check if the output fully incorporates all attributes
    after passing through the Pipeline (Validate -> Normalize -> Extract -> Break components).
    """
    url = "https://google.com"
    result = analyzer.analyze(url)
    
    
    # Verify the validity of the overall result
    assert result.valid is True
    assert result.normalized_url is not None
    assert result.cache_key is not None
    
    # Check Business Rules and break down components (Do not test libraries or mapping structures)
    assert result.components.domain == "google"
    assert result.components.scheme == "https"
    assert result.components.tld == "com"
    
    # Ensure that supplementary attributes are not overlooked
    assert isinstance(result.signals, list)
    assert result.metadata is not None


def test_analyzer_invalid_url(analyzer):
    """
    Case 2: Handling Invalid URLs.
    The system must catch the error, avoid crashing, change the validity to False, and provide an error code.
    """
    url = "not-a-url"
    result = analyzer.analyze(url)
    
    assert result.valid is False
    assert result.error_code is not None
    assert result.error_code == ValidationErrorCode.INVALID_URL_FORMAT.value
    assert isinstance(result.error_message, str)


def test_analyzer_ssrf_allowed(analyzer):
    """
    Case 3: SSRF URLs are no longer blocked from the outset.
    """
    url = "http://127.0.0.1"
    result = analyzer.analyze(url)
    
    assert result.valid is True
    assert result.normalized_url == "http://127.0.0.1"


def test_analyzer_naked_domain(analyzer):
    """
    Case 4: Naked domain without scheme is preprocessed successfully.
    """
    url = "789win.com"
    result = analyzer.analyze(url)
    
    assert result.valid is True
    assert result.normalized_url == "http://789win.com"
    assert result.components.scheme == "http"
    assert result.components.domain == "789win"
    assert result.components.tld == "com"
import pytest
from src.analyzers.url.preprocessing.normalizer import URLNormalizer

@pytest.fixture
def url_normalizer():
    "Fixture provides an initialized instance of URLNormalizer."
    return URLNormalizer()


def test_normalize_lowercase_domain(url_normalizer):
    """Case 1: Convert the protocol and domain name to lowercase"""
    url = "HTTPS://GOOGLE.COM"
    expected = "https://google.com"
    
    result = url_normalizer.normalize(url)
    assert result == expected


def test_normalize_remove_fragment(url_normalizer):
    """Case 2: Remove the fragment (#) after the URL."""
    url = "https://google.com/login#abc"
    expected = "https://google.com/login"
    
    result = url_normalizer.normalize(url)
    assert result == expected


def test_normalize_sort_query_params(url_normalizer):
    """
    Case 3: Sort the query parameters alphabetically.
    """
    url_1 = "https://google.com?b=1&a=2"
    url_2 = "https://google.com?a=2&b=1"
    expected = "https://google.com?a=2&b=1"
    
    assert url_normalizer.normalize(url_1) == expected
    assert url_normalizer.normalize(url_2) == expected


def test_build_cache_key_deterministic(url_normalizer):
    """
    Case 4: Check the stability of the Cache Key.
    """
    url_uppercase = "HTTPS://GOOGLE.COM"
    url_lowercase = "https://google.com"
    normalized_upper = url_normalizer.normalize(url_uppercase)
    normalized_lower = url_normalizer.normalize(url_lowercase)
    key_1 = url_normalizer.build_cache_key(normalized_upper)
    key_2 = url_normalizer.build_cache_key(normalized_lower)
    
    assert key_1 == key_2
    assert key_1.startswith("url:v1:")
    assert len(key_1) == 71
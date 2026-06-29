import pytest
from src.core.enums import URLSignal
from src.analyzers.url.preprocessing.signal_extractor import URLSignalExtractor

@pytest.fixture
def extractor():
    """Fixture provides an initialized instance of URLSignalExtractor."""
    return URLSignalExtractor()


def test_extract_raw_ip(extractor):
    """Case 1: Discovering a Raw Public IP Address."""
    url = "http://8.8.8.8"
    signals, metadata = extractor.extract(url)
    
    assert URLSignal.RAW_IP_ADDRESS.value in signals
    assert URLSignal.PRIVATE_IP_TARGET.value not in signals
    assert metadata.is_ip is True
    assert metadata.is_private_ip is False


def test_extract_private_ip(extractor):
    """Case 2: Simultaneous detection of both raw and internal IP addresses (Private IP Target)."""
    url = "http://192.168.1.1"
    signals, metadata = extractor.extract(url)
    
    assert URLSignal.RAW_IP_ADDRESS.value in signals
    assert URLSignal.PRIVATE_IP_TARGET.value in signals
    assert metadata.is_ip is True
    assert metadata.is_private_ip is True


def test_extract_punycode_domain(extractor):
    """Case 3: Domain name detected containing the xn-- (Punycode) prefix."""
    url = "https://xn--pple-43d.com"
    signals, metadata = extractor.extract(url)
    
    assert URLSignal.PUNYCODE_DOMAIN.value in signals
    assert metadata.is_punycode is True


def test_extract_unicode_domain(extractor):
    """Case 4: Domain name detected containing anonymous Unicode characters (Homograph Phishing)."""
    url = "https://аррӏе.com"
    signals, metadata = extractor.extract(url)
    
    assert URLSignal.UNICODE_DOMAIN.value in signals
    assert metadata.contains_unicode is True


def test_extract_suspicious_tld(extractor):
    """Case 5: Domain name extension detected as suspicious (.xyz)."""
    url = "https://abc.xyz"
    signals, metadata = extractor.extract(url)
    
    assert URLSignal.SUSPICIOUS_TLD.value in signals


def test_extract_benign_url(extractor):
    """Case 6: Clean URL (Benign), does not trigger any warnings or signal labels."""
    url = "https://google.com"
    signals, metadata = extractor.extract(url)
    
    assert signals == []
    assert metadata.is_ip is False
    assert metadata.is_private_ip is False
    assert metadata.is_punycode is False
    assert metadata.contains_unicode is False
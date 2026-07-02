from __future__ import annotations
import pytest
from src.core.models import PageSnapshot, RedirectAnalysis
from src.analyzers.url.dynamic_analysis.redirect.redirect_analyzer import RedirectAnalyzer

def create_mock_snapshot(redirect_chain: list[str]) -> PageSnapshot:
    """Helper to instantiate a mock PageSnapshot with a custom redirect chain."""
    return PageSnapshot(
        original_url=redirect_chain[0] if len(redirect_chain) > 0 else "",
        final_url=redirect_chain[-1] if len(redirect_chain) > 0 else "",
        status_code=200,
        title="Mock Title",
        html="<html></html>",
        load_time_ms=100.0,
        redirect_chain=redirect_chain
    )

def test_redirect_analyzer_no_redirects():
    """Verify that a snapshot with zero redirects registers no flags or count."""
    snapshot = create_mock_snapshot(["https://example.com"])
    
    analyzer = RedirectAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert isinstance(result, RedirectAnalysis)
    assert result.redirect_count == 0
    assert result.redirect_chain == ["https://example.com"]
    assert result.has_redirect_loop is False
    assert result.has_cross_domain_redirect is False
    assert result.redirects_to_ip is False
    assert result.redirects_to_localhost is False
    assert result.redirects_to_private_ip is False


def test_redirect_analyzer_cross_domain():
    """Verify cross-domain redirect changes are flagged correctly."""
    snapshot = create_mock_snapshot([
        "https://example.com", 
        "https://sub.example.com",  # same apex domain
        "https://other-domain.xyz"  # cross-domain
    ])
    
    analyzer = RedirectAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.redirect_count == 2
    assert result.has_cross_domain_redirect is True
    assert result.has_redirect_loop is False


def test_redirect_analyzer_circular_loop():
    """Verify circular paths in redirections are flagged."""
    snapshot = create_mock_snapshot([
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/a/"  # loop (ignoring trailing slash)
    ])
    
    analyzer = RedirectAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.redirect_count == 2
    assert result.has_redirect_loop is True


def test_redirect_analyzer_localhost_and_private_ip():
    """Verify localhost loopbacks and private subnet redirection targets are flagged."""
    snapshot = create_mock_snapshot([
        "https://example.com",
        "http://localhost/login",
        "http://10.0.0.5/api"
    ])
    
    analyzer = RedirectAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.redirect_count == 2
    assert result.redirects_to_ip is True  # 10.0.0.5 is an IP
    assert result.redirects_to_localhost is True  # localhost is loopback
    assert result.redirects_to_private_ip is True  # both localhost and 10.0.0.5 are private


def test_redirect_analyzer_public_ip():
    """Verify public IP redirection is flagged as IP but not loopback/private."""
    snapshot = create_mock_snapshot([
        "https://example.com",
        "http://8.8.8.8/dns"
    ])
    
    analyzer = RedirectAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.redirect_count == 1
    assert result.redirects_to_ip is True
    assert result.redirects_to_localhost is False
    assert result.redirects_to_private_ip is False

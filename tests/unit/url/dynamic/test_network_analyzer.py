from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from src.core.models import NetworkAnalysis
from src.analyzers.url.dynamic_analysis.network.network_analyzer import NetworkAnalyzer

class MockEventPage:
    """Mock implementation of Playwright Page supporting event listener registers/deregisters."""
    def __init__(self):
        self.listeners = {}

    def on(self, event: str, callback):
        self.listeners[event] = callback

    def remove_listener(self, event: str, callback):
        if event in self.listeners:
            del self.listeners[event]

    def trigger(self, event: str, *args, **kwargs):
        if event in self.listeners:
            self.listeners[event](*args, **kwargs)

class MockPlaywrightRequest:
    """Mock implementation of Playwright Request."""
    def __init__(self, url: str, method: str, resource_type: str):
        self.url = url
        self.method = method
        self.resource_type = resource_type

class MockPlaywrightResponse:
    """Mock implementation of Playwright Response."""
    def __init__(self, url: str, status: int):
        self.url = url
        self.status = status

class MockPlaywrightWebSocket:
    """Mock implementation of Playwright WebSocket."""
    def __init__(self, url: str):
        self.url = url


def test_network_analyzer_capture_metrics():
    """Verify that NetworkAnalyzer captures, filters, and analyzes network requests and websockets."""
    session = MagicMock()
    page = MockEventPage()
    session.page = page

    analyzer = NetworkAnalyzer()
    analyzer.start_capture(session, "https://example.com/index.html")

    # Simulate network requests
    req1 = MockPlaywrightRequest("https://example.com/logo.png", "GET", "image")
    req2 = MockPlaywrightRequest("https://static.example.com/style.css", "GET", "stylesheet")
    req3 = MockPlaywrightRequest("https://cdnjs.cloudflare.com/cdn.js", "GET", "script")
    req4 = MockPlaywrightRequest("https://api.google.com/search", "POST", "fetch")
    req_fail = MockPlaywrightRequest("https://example.com/404", "GET", "document")

    page.trigger("request", req1)
    page.trigger("request", req2)
    page.trigger("request", req3)
    page.trigger("request", req4)
    page.trigger("request", req_fail)

    # Simulate responses
    page.trigger("response", MockPlaywrightResponse("https://example.com/logo.png", 200))
    page.trigger("response", MockPlaywrightResponse("https://static.example.com/style.css", 200))
    page.trigger("response", MockPlaywrightResponse("https://cdnjs.cloudflare.com/cdn.js", 200))
    page.trigger("response", MockPlaywrightResponse("https://api.google.com/search", 200))

    # Simulate request failure
    page.trigger("requestfailed", req_fail)

    # Simulate websocket connection
    page.trigger("websocket", MockPlaywrightWebSocket("wss://example.com/realtime"))

    # Finish capture
    result = analyzer.stop_capture()

    assert isinstance(result, NetworkAnalysis)
    assert result.request_count == 5
    assert result.response_count == 4

    # External hostnames (any host other than exact example.com)
    assert "static.example.com" in result.external_domains
    assert "cdnjs.cloudflare.com" in result.external_domains
    assert "api.google.com" in result.external_domains
    assert "example.com" not in result.external_domains

    # Third party domains (different apex/registrable domains than example.com)
    assert "cloudflare.com" in result.third_party_domains
    assert "google.com" in result.third_party_domains
    # static.example.com apex is example.com, so it should NOT be in third_party
    assert "example.com" not in result.third_party_domains

    # CDN domains (matches Cloudflare from keywords)
    assert "cdnjs.cloudflare.com" in result.cdn_domains

    # API endpoints (res_type "fetch")
    assert result.api_endpoints == ["https://api.google.com/search"]

    # Websockets
    assert result.websocket_connections == ["wss://example.com/realtime"]

    # Failed requests
    assert result.failed_requests == ["https://example.com/404"]

    # Verify state collections are completely reset
    assert analyzer._page is None
    assert len(analyzer._requests) == 0
    assert len(analyzer._responses) == 0
    assert len(analyzer._websocket_urls) == 0
    assert len(analyzer._failed_urls) == 0
    assert analyzer._initial_url is None

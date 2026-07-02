from __future__ import annotations
import urllib.parse
from typing import Any
from src.core.models import NetworkAnalysis
from src.analyzers.url.dynamic_analysis.browser_engine import BrowserSession
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain

class NetworkAnalyzer:
    """Analyzer responsible for capturing and categorizing page network logs."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()
        self._page: Any = None
        self._requests: list[dict[str, Any]] = []
        self._responses: list[dict[str, Any]] = []
        self._websocket_urls: list[str] = []
        self._failed_urls: list[str] = []
        self._initial_url: str | None = None

    def is_capturing(self) -> bool:
        """Check if active page logging is in progress."""
        return self._page is not None

    def start_capture(self, session: BrowserSession, initial_url: str) -> None:
        """Register Playwright page listeners to start capturing network events."""
        self._page = session.page
        self._requests = []
        self._responses = []
        self._websocket_urls = []
        self._failed_urls = []
        self._initial_url = initial_url
        
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("websocket", self._on_websocket)
        self._page.on("requestfailed", self._on_request_failed)

    def stop_capture(self) -> NetworkAnalysis:
        """Deregister listeners and analyze captured network events."""
        if not self._page:
            return NetworkAnalysis()
            
        try:
            self._page.remove_listener("request", self._on_request)
            self._page.remove_listener("response", self._on_response)
            self._page.remove_listener("websocket", self._on_websocket)
            self._page.remove_listener("requestfailed", self._on_request_failed)
        except Exception:
            # Safeguard listener removal issues in closed browser scenarios
            pass
        
        result = self._analyze_metrics()
        
        # Reset and clear all state collections to prevent memory leaks or data cross-contamination
        self._page = None
        self._requests.clear()
        self._responses.clear()
        self._websocket_urls.clear()
        self._failed_urls.clear()
        self._initial_url = None
        
        return result

    def _on_request(self, request: Any) -> None:
        self._requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        })

    def _on_response(self, response: Any) -> None:
        self._responses.append({
            "url": response.url,
            "status": response.status,
        })

    def _on_websocket(self, websocket: Any) -> None:
        self._websocket_urls.append(websocket.url)

    def _on_request_failed(self, request: Any) -> None:
        self._failed_urls.append(request.url)

    def _analyze_metrics(self) -> NetworkAnalysis:
        if not self._initial_url:
            return NetworkAnalysis()
            
        try:
            parsed_initial = urllib.parse.urlparse(self._initial_url)
            initial_host = parsed_initial.hostname or ""
            initial_apex = get_apex_domain(self._initial_url)
        except Exception:
            initial_host = ""
            initial_apex = ""
            
        external_domains_set = set()
        third_party_domains_set = set()
        cdn_domains_set = set()
        api_endpoints = []
        
        for req in self._requests:
            url = req["url"]
            res_type = req["resource_type"]
            
            try:
                parsed_url = urllib.parse.urlparse(url)
                host = parsed_url.hostname or ""
            except Exception:
                host = ""
                
            if not host:
                continue
                
            # Check external domains (subdomains or different hosts)
            if host.lower() != initial_host.lower():
                external_domains_set.add(host)
                
            # Check third-party domains (different apex domains)
            host_apex = get_apex_domain(url)
            if host_apex and initial_apex and host_apex.lower() != initial_apex.lower():
                third_party_domains_set.add(host_apex)
                
            # Check CDN domains
            if any(kw in host.lower() for kw in self.config.CDN_KEYWORDS):
                cdn_domains_set.add(host)
                
            # Check API endpoints (XHR/fetch or paths with /api/ or json)
            if res_type in ["fetch", "xhr"] or "/api/" in url.lower() or ".json" in url.lower():
                api_endpoints.append(url)
                
        return NetworkAnalysis(
            request_count=len(self._requests),
            response_count=len(self._responses),
            external_domains=sorted(list(external_domains_set)),
            third_party_domains=sorted(list(third_party_domains_set)),
            cdn_domains=sorted(list(cdn_domains_set)),
            api_endpoints=api_endpoints,
            websocket_connections=sorted(list(set(self._websocket_urls))),
            failed_requests=sorted(list(set(self._failed_urls)))
        )

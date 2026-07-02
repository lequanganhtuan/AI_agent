from __future__ import annotations

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.urlscan_provider import (
    URLScanProvider,
)
from src.core.models import URLScanAnalysis


# =========================================================================
# FIXTURES
# =========================================================================

@pytest.fixture
def target_input() -> ThreatIntelInput:
    """Provides a normalized URL input DTO for coordinating lookups."""
    return ThreatIntelInput(
        normalized_url="http://example.com/malicious",
        domain="example.com",
    )


@pytest.fixture
def provider(monkeypatch) -> URLScanProvider:
    """Initializes the URLScanProvider client in a fixture."""
    with patch("src.analyzers.url.threat_intelligence.provider.urlscan_provider.settings") as mock_settings:
        mock_settings.urlscan_api_key = "test_urlscan_api_key_123"
        urlscan_provider = URLScanProvider()
        monkeypatch.setattr(urlscan_provider, "_poll_interval", 0.0001)
        return urlscan_provider


# =========================================================================
# TESTS
# =========================================================================

class TestURLScanProvider:

    # 0. successful init & missing config
    def test_init_success(self):
        with patch("src.analyzers.url.threat_intelligence.provider.urlscan_provider.settings") as mock_settings:
            mock_settings.urlscan_api_key = "api_key_123"
            prov = URLScanProvider()
            assert prov._api_key == "api_key_123"

    def test_init_missing_key(self):
        with patch("src.analyzers.url.threat_intelligence.provider.urlscan_provider.settings") as mock_settings:
            mock_settings.urlscan_api_key = ""
            with pytest.raises(ValueError) as exc_info:
                URLScanProvider()
            assert "URLSCAN_API_KEY is not configured" in str(exc_info.value)

    # 1. test_submit_url
    @pytest.mark.anyio
    async def test_submit_url_success(self, provider):
        """valid URL → returns uuid"""
        mock_response = httpx.Response(
            status_code=200,
            json={"uuid": "4abc-1234-abcd", "result": "https://urlscan.io/result/4abc-1234-abcd/"},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            uuid_val = await provider._submit_url("http://example.com")
            assert uuid_val == "4abc-1234-abcd"

    @pytest.mark.anyio
    async def test_submit_url_missing_uuid(self, provider):
        """missing uuid → exception"""
        mock_response = httpx.Response(
            status_code=200,
            json={"result_url_but_no_uuid": "some_value"},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            with pytest.raises(ProviderError) as exc_info:
                await provider._submit_url("http://example.com")
            assert "Missing UUID identifier" in str(exc_info.value.message)

    @pytest.mark.anyio
    async def test_submit_url_api_error(self, provider):
        """API error → ProviderError"""
        mock_response = httpx.Response(
            status_code=400,
            json={"error": {"message": "Invalid API Key", "code": 401}},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            with pytest.raises(ProviderError) as exc_info:
                await provider._submit_url("http://example.com")
            assert "URLScan API Internal Business Error" in str(exc_info.value.message)
            assert exc_info.value.status_code == 401

    # 2. test_poll_result_success
    @pytest.mark.anyio
    async def test_poll_result_success(self, provider):
        """status = done → return response, pending/processing → loop continues"""
        mock_r1 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})  # pending (standard 404)
        mock_r2 = httpx.Response(status_code=200, json={"status": "processing"}, headers={"Content-Type": "application/json"})  # processing
        mock_r3 = httpx.Response(status_code=200, json={"status": "done", "page": {}}, headers={"Content-Type": "application/json"})  # done

        mock_get = AsyncMock(side_effect=[mock_r1, mock_r2, mock_r3])
        with patch.object(provider, "_get_result", mock_get):
            res = await provider._poll_result("some-uuid")
            assert res == mock_r3
            assert mock_get.call_count == 3

    # 3. test_poll_result_timeout
    @pytest.mark.anyio
    async def test_poll_result_timeout(self, provider, monkeypatch):
        """never reaches done → ProviderError(408)"""
        monkeypatch.setattr(provider, "_max_poll_attempts", 2)
        mock_r1 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})

        with patch.object(provider, "_get_result", AsyncMock(return_value=mock_r1)):
            with pytest.raises(ProviderError) as exc_info:
                await provider._poll_result("some-uuid")
            assert exc_info.value.status_code == 408
            assert "Polling lifecycle expired" in str(exc_info.value.message)

    # 4. test_parse_response_valid
    def test_parse_response_valid(self, provider):
        """full JSON valid → correct DTO mapping"""
        payload = {
            "task": {
                "uuid": "uuid-1234",
                "screenshotURL": "https://urlscan.io/screenshots/uuid-1234.png",
                "domSizeBytes": 5000
            },
            "page": {
                "title": "Example Page",
                "ip": "1.2.3.4",
                "country": "US",
                "asn": "AS15169"
            },
            "lists": {
                "urls": ["https://outgoing.com/link"]
            },
            "verdicts": {
                "overall": {
                    "malicious": True,
                    "score": 85,
                    "tags": ["phishing", "malware"]
                }
            },
            "data": {
                "redirects": ["http://example.com", "https://redirect-target.com"]
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        analysis = provider.parse_response(res, "uuid-1234")
        assert isinstance(analysis, URLScanAnalysis)
        assert analysis.screenshot_url == "https://urlscan.io/screenshots/uuid-1234.png"
        assert analysis.dom_size == 5000
        assert analysis.redirect_count == 2
        assert analysis.external_links == ["https://outgoing.com/link"]
        assert analysis.ip_address == "1.2.3.4"
        assert analysis.country == "US"
        assert analysis.malicious_score == 85
        assert analysis.tags == ["malware", "phishing"]
        assert analysis.scan_id == "uuid-1234"

    # 5. test_parse_response_missing_fields
    def test_parse_response_missing_fields(self, provider):
        """missing screenshot → handled gracefully, missing ip → None fallback"""
        payload = {
            "task": {
                "uuid": "uuid-1234"
                # screenshotURL and domSizeBytes are missing
            },
            "page": {
                # ip and country are missing
            },
            "verdicts": {
                "overall": {}
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        analysis = provider.parse_response(res, "uuid-1234")
        assert analysis.screenshot_url is None
        assert analysis.dom_size == 0
        assert analysis.ip_address is None
        assert analysis.country is None
        assert analysis.malicious_score == 0
        assert analysis.tags == []

    # 6. test_validate_payload
    def test_validate_payload_invalid_type(self, provider):
        res = httpx.Response(status_code=200, json="not_a_dict", headers={"Content-Type": "application/json"})
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_and_extract_json(res)
        assert "JSON root is not an object model" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502

    def test_validate_payload_error_block(self, provider):
        res = httpx.Response(status_code=200, json={"error": {"message": "Access Denied", "code": 403}}, headers={"Content-Type": "application/json"})
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_and_extract_json(res)
        assert "URLScan API Internal Business Error" in str(exc_info.value.message)
        assert "Access Denied" in str(exc_info.value.message)
        assert exc_info.value.status_code == 403

    def test_validate_payload_missing_required_keys(self, provider):
        res = httpx.Response(status_code=200, json={"other_key": "some_val"}, headers={"Content-Type": "application/json"})
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res, "uuid-123")
        assert "Integrity check failed" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502

    # 7. test_extract_links
    def test_extract_links(self, provider):
        """normal list → correct, mixed invalid items → filtered, empty → []"""
        data = {
            "lists": {
                "urls": [
                    "https://valid.com",
                    "http://also-valid.org/path",
                    "invalid-scheme.com",
                    "",
                    None,
                    12345
                ]
            }
        }
        extracted = provider._extract_network_data(data)["external_links"]
        assert extracted == ["https://valid.com", "http://also-valid.org/path"]
        assert provider._extract_network_data({})["external_links"] == []

    # 8. test_security_signals
    def test_security_signals(self, provider):
        """phishing tag present → detected, malware score high → flagged"""
        data = {
            "verdicts": {
                "overall": {
                    "malicious": True,
                    "score": 99,
                    "tags": ["phishing", "malware", "phishing"]  # duplicates
                }
            }
        }
        signals = provider._extract_security_signals(data)
        assert signals["score"] == 99
        assert signals["phishing_tags"] == ["malware", "phishing"]

    # 9. test_lookup_orchestrator
    @pytest.mark.anyio
    async def test_lookup_orchestrator_success(self, provider, target_input):
        mock_response = httpx.Response(
            status_code=200,
            json={
                "task": {"uuid": "uuid-123", "screenshotURL": "https://screenshot.png"},
                "page": {"country": "SG"},
                "verdicts": {"overall": {}}
            },
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_submit_url", AsyncMock(return_value="uuid-123")), \
             patch.object(provider, "_poll_result", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, URLScanAnalysis)
            assert res.screenshot_url == "https://screenshot.png"
            assert res.country == "SG"
            await provider.close()

    @pytest.mark.anyio
    async def test_lookup_orchestrator_submit_fails(self, provider, target_input):
        with patch.object(provider, "_submit_url", AsyncMock(side_effect=ProviderError("URLScan", "Submit Fail", 500))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "Submit Fail" in str(exc_info.value.message)
        await provider.close()

    @pytest.mark.anyio
    async def test_lookup_orchestrator_poll_fails(self, provider, target_input):
        with patch.object(provider, "_submit_url", AsyncMock(return_value="uuid-123")), \
             patch.object(provider, "_poll_result", AsyncMock(side_effect=ProviderError("URLScan", "Timeout Poll", 408))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "Timeout Poll" in str(exc_info.value.message)
        await provider.close()

    @pytest.mark.anyio
    async def test_lookup_orchestrator_parse_fails(self, provider, target_input):
        mock_response = httpx.Response(status_code=200, json={"verdicts": {}}, headers={"Content-Type": "application/json"})
        with patch.object(provider, "_submit_url", AsyncMock(return_value="uuid-123")), \
             patch.object(provider, "_poll_result", AsyncMock(return_value=mock_response)), \
             patch.object(provider, "parse_response", side_effect=ValueError("Parse failed")):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "Lookup orchestration failed unexpectedly:" in str(exc_info.value.message)
        await provider.close()

    # 10. test_rate_limit_handling
    @pytest.mark.anyio
    async def test_rate_limit_handling_429(self, provider, target_input):
        """HTTP 429 → ProviderError preserved"""
        # _safe_request converts 429 into ProviderError(429)
        with patch.object(provider, "_safe_request", AsyncMock(side_effect=ProviderError("URLScan", "Rate limit exceeded.", 429))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 429
            assert "Rate limit exceeded" in str(exc_info.value.message)
        await provider.close()

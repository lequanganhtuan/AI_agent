from __future__ import annotations

import base64
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.virustotal_provider import (
    VirusTotalProvider,
)
from src.core.models import VirusTotalAnalysis


# =========================================================================
# FIXTURES
# =========================================================================

@pytest.fixture
def target_input() -> ThreatIntelInput:
    """Provides a normalized URL input DTO for coordinating lookups."""
    return ThreatIntelInput(
        normalized_url="https://example.com/malicious-path",
        domain="example.com",
    )


@pytest.fixture
def provider(monkeypatch) -> VirusTotalProvider:
    """Initializes the VirusTotalProvider client in a synchronous fixture.
    Safe for both sync and async test cases.
    """
    with patch("src.analyzers.url.threat_intelligence.provider.virustotal_provider.settings") as mock_settings:
        mock_settings.virustotal_api_key = "prod_enterprise_token_secret_xyz"
        vt_provider = VirusTotalProvider()
        # Suppress polling delay for faster test execution
        monkeypatch.setattr(vt_provider, "_poll_interval", 0.0001)
        return vt_provider


# =========================================================================
# CLASS 1: TEST INITIALIZATION
# =========================================================================
class TestInitialization:
    
    def test_init_success(self):
        """Verify successful initialization with API key and headers configured correctly."""
        with patch("src.analyzers.url.threat_intelligence.provider.virustotal_provider.settings") as mock_settings:
            mock_settings.virustotal_api_key = "secure_token_v3"
            instance = VirusTotalProvider()
            assert instance.client.headers["x-apikey"] == "secure_token_v3"
            assert instance.client.headers["Accept"] == "application/json"

    def test_init_missing_key(self):
        """Verify ValueError is raised if the VirusTotal API key is missing."""
        with patch("src.analyzers.url.threat_intelligence.provider.virustotal_provider.settings") as mock_settings:
            mock_settings.virustotal_api_key = ""
            with pytest.raises(ValueError) as exc_info:
                VirusTotalProvider()
            assert "VIRUSTOTAL_API_KEY is not configured" in str(exc_info.value)


# =========================================================================
# CLASS 2: TEST LOOKUP
# =========================================================================
@pytest.mark.anyio
class TestLookup:
    @pytest.fixture(autouse=True)
    async def cleanup_provider_client(self, provider):
        yield
        await provider.close()

    async def test_lookup_cached(self, provider, target_input):
        """Test lookup when report is cached and returned with clean status (found=False)."""
        mock_cached_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"harmless": 70, "malicious": 0, "suspicious": 0, "undetected": 5},
                    "last_analysis_results": {},
                    "last_analysis_date": 1688000000
                }
            }
        }
        mock_response = httpx.Response(
            status_code=200, json=mock_cached_data, headers={"Content-Type": "application/json"}
        )

        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            result = await provider.lookup(target_input)
            assert isinstance(result, VirusTotalAnalysis)
            assert result.found is False
            assert result.malicious == 0
            assert result.total_engines == 75

    async def test_lookup_submit_and_complete(self, provider, target_input):
        """Test full workflow polling from queued, in-progress, and completed states."""
        mock_get_404 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})
        mock_post_submit = httpx.Response(
            status_code=200, json={"data": {"id": "analysis_id_complex_123"}}, headers={"Content-Type": "application/json"}
        )
        
        mock_q1 = httpx.Response(status_code=200, json={"data": {"attributes": {"status": "queued"}}}, headers={"Content-Type": "application/json"})
        mock_q2 = httpx.Response(status_code=200, json={"data": {"attributes": {"status": "queued"}}}, headers={"Content-Type": "application/json"})
        mock_ip = httpx.Response(status_code=200, json={"data": {"attributes": {"status": "in-progress"}}}, headers={"Content-Type": "application/json"})
        mock_comp = httpx.Response(
            status_code=200,
            json={
                "data": {
                    "attributes": {
                        "status": "completed",
                        "stats": {"harmless": 50, "malicious": 1},
                        "results": {},
                        "date": 1688009000
                    }
                }
            },
            headers={"Content-Type": "application/json"}
        )

        mock_stream = AsyncMock(side_effect=[mock_get_404, mock_post_submit, mock_q1, mock_q2, mock_ip, mock_comp])

        with patch.object(provider, "_safe_request", mock_stream):
            result = await provider.lookup(target_input)
            assert mock_stream.call_count == 6
            assert isinstance(result, VirusTotalAnalysis)
            assert result.found is True

    async def test_lookup_timeout(self, provider, target_input, monkeypatch):
        """Verify that lookup raises a 408 ProviderError if polling attempts are exceeded."""
        monkeypatch.setattr(provider, "_max_poll_attempts", 2)
        mock_get_404 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})
        mock_post_submit = httpx.Response(
            status_code=200, json={"data": {"id": "job_id"}}, headers={"Content-Type": "application/json"}
        )
        mock_poll_running = httpx.Response(
            status_code=200, json={"data": {"attributes": {"status": "in-progress"}}}, headers={"Content-Type": "application/json"}
        )

        with patch.object(provider, "_safe_request", AsyncMock(side_effect=[mock_get_404, mock_post_submit, mock_poll_running, mock_poll_running])):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 408

    async def test_lookup_provider_error(self, provider, target_input):
        """Verify that lookup propagates network/provider errors correctly."""
        with patch.object(provider, "_safe_request", AsyncMock(side_effect=ProviderError("VirusTotal", "Quota limit", 429))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 429

    async def test_lookup_invalid_polling_state(self, provider, target_input):
        """Verify that lookup raises ProviderError when polling hits a failed/terminated status."""
        mock_get_404 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})
        mock_post_submit = httpx.Response(
            status_code=200, json={"data": {"id": "analysis_id"}}, headers={"Content-Type": "application/json"}
        )
        mock_poll_failed = httpx.Response(
            status_code=200, json={"data": {"attributes": {"status": "failed"}}}, headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(side_effect=[mock_get_404, mock_post_submit, mock_poll_failed])):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "unexpected status: 'failed'" in str(exc_info.value)

    async def test_lookup_handling_text_html(self, provider, target_input):
        """Verify that lookup raises ProviderError when receiving text/html content type (WAF block)."""
        mock_response = httpx.Response(
            status_code=200, text="<html>Cloudflare WAF Blocked</html>", headers={"Content-Type": "text/html"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "Expected JSON response" in str(exc_info.value)

    async def test_lookup_handling_error_payload_in_http_200(self, provider, target_input):
        """Verify that lookup raises ProviderError when receiving an error block nested in an HTTP 200."""
        mock_response = httpx.Response(
            status_code=200,
            json={"error": {"code": "WrongCredentials", "message": "API Key is invalid"}},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert "API Business Error [WrongCredentials]" in str(exc_info.value)


# =========================================================================
# CLASS 3: TEST PARSER (Hàm đồng bộ thuần túy)
# =========================================================================
class TestParser:

    def test_parse_cached_schema(self, provider):
        """Verify parser handles schema from historical/cached endpoint (GET /urls/{id})."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"harmless": 30, "malicious": 5},
                    "last_analysis_results": {"AV1": {"category": "malicious", "result": "Trojan.Agent"}},
                    "last_analysis_date": 1688000000
                }
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        dto = provider.parse_response(res)
        assert dto.total_engines == 35
        assert dto.malicious == 5

    def test_parse_analysis_schema(self, provider):
        """Verify parser handles schema from analysis/polling endpoint (GET /analyses/{id})."""
        payload = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"harmless": 20, "malicious": 2, "confirmed-timeout": 3},
                    "results": {},
                    "date": 1688000000
                }
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        dto = provider.parse_response(res)
        assert dto.total_engines == 25
        assert dto.malicious == 2

    def test_parse_invalid_schema(self, provider):
        """Verify parser fails gracefully if core fields are completely corrupted."""
        res = httpx.Response(status_code=200, json={"corrupted": "shape"}, headers={"Content-Type": "application/json"})
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Failed to parse internal schema fields" in str(exc_info.value)

    def test_parse_missing_fields(self, provider):
        """Verify parser falls back cleanly when attributes and results are partially missing."""
        payload_missing = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3, "suspicious": 0, "undetected": 1
                    },
                    "last_analysis_results": {
                        "AV_NoCategory": {"result": "Worm.Generic"},
                    },
                    "results": None,
                    "last_analysis_date": None
                }
            }
        }
        res = httpx.Response(status_code=200, json=payload_missing, headers={"Content-Type": "application/json"})
        dto = provider.parse_response(res)
        
        assert dto.harmless == 0
        assert dto.total_engines == 4
        assert dto.categories == []
        assert dto.scan_date is None

    def test_parse_missing_all_stats(self, provider):
        """Verify parser raises ProviderError when both statistics structures are absent."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_date": 1688000000
                }
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Neither 'last_analysis_stats' nor 'stats' found" in str(exc_info.value)

    def test_parse_additional_stats_and_results_edge_cases(self, provider):
        """Verify parser behavior with extra stats (timeout, failure) and empty engine results."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 10,
                        "malicious": 1,
                        "suspicious": 1,
                        "undetected": 5,
                        "timeout": 2,
                        "failure": 1,
                    },
                    "last_analysis_results": {
                        "Engine1": {"category": "malicious", "result": "trojan"},
                        "Engine2": {"category": "malicious", "result": None},
                        "Engine3": {"category": "harmless", "result": None},
                    },
                    "last_analysis_date": 1688000000
                }
            }
        }
        res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
        dto = provider.parse_response(res)
        
        assert dto.total_engines == 20
        assert dto.malicious == 1
        assert dto.suspicious == 1
        assert dto.categories == ["trojan"]
        assert dto.found is True


# =========================================================================
# CLASS 4: TEST HELPERS (Hàm đồng bộ thuần túy)
# =========================================================================
class TestHelpers:

    def test_build_url_id(self, provider):
        """Verify Base64 encoding strips equals padding according to specifications."""
        url_input = "https://google.com?query=param=="
        url_id = provider._build_url_id(url_input)
        
        decoded = base64.urlsafe_b64decode(provider._build_url_id(url_input) + "=" * (4 - len(url_id) % 4)).decode("utf-8")
        assert decoded == url_input
        assert "=" not in url_id

    def test_extract_status(self, provider):
        """Verify status extraction maps queued, completed, in-progress correctly."""
        statuses = ["completed", "queued", "in-progress"]
        for current_status in statuses:
            payload = {"data": {"attributes": {"status": current_status}}}
            res = httpx.Response(status_code=200, json=payload, headers={"Content-Type": "application/json"})
            assert provider._extract_status(res) == current_status

    def test_extract_statistics(self, provider):
        """Verify statistics extraction parses both polymorphic attributes structures."""
        stats, _ = provider._extract_statistics({"last_analysis_stats": {"harmless": 10}})
        assert stats["harmless"] == 10
        stats, _ = provider._extract_statistics({"stats": {"malicious": 5}})
        assert stats["malicious"] == 5

    def test_extract_categories(self, provider):
        """Verify categories deduplicates threat signature values and skips clean categories."""
        mock_results = {
            "Engine1": {"category": "malicious", "result": "trojan"},
            "Engine2": {"category": "malicious", "result": "phishing"},
            "Engine3": {"category": "malicious", "result": "trojan"},
            "Engine4": {"category": "suspicious", "result": "trojan"},
            "Engine5": {"category": "harmless", "result": "clean"}
        }
        deduped_list = provider._extract_categories(mock_results)
        assert len(deduped_list) == 2
        assert set(deduped_list) == {"trojan", "phishing"}

    def test_extract_scan_date(self, provider):
        """Verify extraction of timezone-aware UTC dates and recovery on corrupted values."""
        dt_val = provider._extract_scan_date({"date": 1688000000})
        assert isinstance(dt_val, datetime)
        assert dt_val.year == 2023
        
        assert provider._extract_scan_date({"date": "abc_corrupted_payload"}) is None

    def test_is_not_found(self, provider):
        """Verify defensive boundary checks for missing records (404 and NotFoundError)."""
        res_404 = httpx.Response(status_code=404, headers={"Content-Type": "application/json"})
        assert provider._is_not_found(res_404) is True
        
        res_biz_404 = httpx.Response(
            status_code=400, json={"error": {"code": "NotFoundError"}}, headers={"Content-Type": "application/json"}
        )
        assert provider._is_not_found(res_biz_404) is True

        res_500 = httpx.Response(status_code=500, json={}, headers={"Content-Type": "application/json"})
        assert provider._is_not_found(res_500) is False

    def test_validate_content_type(self, provider):
        """Verify validation blocks HTML pages and proxies correctly."""
        res_html = httpx.Response(status_code=429, text="<html>Blocked</html>", headers={"Content-Type": "text/html"})
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_response_content_type(res_html)
        assert "Expected JSON response but received Content-Type 'text/html'" in str(exc_info.value)

        # JSON content-type should pass through without an exception
        res_json = httpx.Response(status_code=200, headers={"Content-Type": "application/json"})
        provider._validate_response_content_type(res_json)

    def test_validate_business_error(self, provider):
        """Verify validation intercepts nested error schemas inside HTTP 200/400-level payload."""
        payload_err = {"error": {"code": "WrongCredentialsError", "message": "Invalid API key provided"}}
        res = httpx.Response(status_code=401, json=payload_err, headers={"Content-Type": "application/json"})
        
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_business_error(payload_err, res)
        assert "API Business Error [WrongCredentialsError]" in str(exc_info.value)
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.urlhaus_provider import (
    URLHausProvider,
)
from src.core.models import URLHausAnalysis


# =========================================================================
# FIXTURES
# =========================================================================

@pytest.fixture
def target_input() -> ThreatIntelInput:
    """Provides a normalized URL input DTO for coordinating lookups."""
    return ThreatIntelInput(
        normalized_url="http://example.com/malware",
        domain="example.com",
    )


@pytest.fixture
def provider() -> URLHausProvider:
    """Initializes the URLHausProvider client in a fixture."""
    with patch("src.analyzers.url.threat_intelligence.provider.urlhaus_provider.settings") as mock_settings:
        mock_settings.urlhaus_api_key = "test_urlhaus_api_key_123"
        return URLHausProvider()


# =========================================================================
# 1. TestInitialization
# =========================================================================
class TestInitialization:

    def test_init_success(self, provider):
        """Verify successful initialization and field setting."""
        assert provider.PROVIDER_NAME == "URLHaus"
        assert "urlhaus-api.abuse.ch" in provider._endpoint
        assert "/v1/url/" in provider._endpoint


# =========================================================================
# 2. TestLookup
# =========================================================================
@pytest.mark.anyio
class TestLookup:

    @pytest.fixture(autouse=True)
    async def cleanup_provider_client(self, provider):
        yield
        await provider.close()

    async def test_lookup_clean_success(self, provider, target_input):
        """URL clean (no_results)"""
        mock_response = httpx.Response(
            status_code=200,
            json={"query_status": "no_results"},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, URLHausAnalysis)
            assert res.query_status == "no_results"
            assert res.url_status is None
            assert res.threat is None
            assert res.tags == []
            assert res.payloads == []

    async def test_lookup_malicious_success(self, provider, target_input):
        """URL malicious (ok)"""
        mock_response = httpx.Response(
            status_code=200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["cobaltstrike", "exe"],
                "reporter": "some_guy",
                "firstseen": "2025-05-01 11:20:30 UTC",
                "payloads": [{"md5": "abc"}]
            },
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, URLHausAnalysis)
            assert res.query_status == "ok"
            assert res.url_status == "online"
            assert res.threat == "malware_download"
            assert res.tags == ["cobaltstrike", "exe"]
            assert res.reporter == "some_guy"
            assert res.first_seen == datetime(2025, 5, 1, 11, 20, 30, tzinfo=timezone.utc)
            assert res.payloads == [{"md5": "abc"}]

    async def test_lookup_validation_failed(self, provider):
        """Validate input URLhaus"""
        bad_input = ThreatIntelInput(normalized_url="", domain="example.com")
        with pytest.raises(ValueError) as exc_info:
            await provider.lookup(bad_input)
        assert "Target input normalized_url cannot be null or empty" in str(exc_info.value)

    async def test_lookup_propagates_provider_error(self, provider, target_input):
        """ProviderError propagates directly"""
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=ProviderError("URLHaus", "Rate Limit", 429))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 429
            assert "Rate Limit" in str(exc_info.value.message)

    async def test_lookup_wraps_general_exception(self, provider, target_input):
        """Exception wrapped into ProviderError"""
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=ValueError("Socket closed"))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 500
            assert "Lookup failed:" in str(exc_info.value.message)


# =========================================================================
# 3. TestBuildRequestPayload
# =========================================================================
class TestBuildRequestPayload:

    def test_build_request_payload(self, provider, target_input):
        payload = provider._build_request_payload(target_input)
        assert payload == {"url": target_input.normalized_url}


# =========================================================================
# 4. TestPostLookup
# =========================================================================
@pytest.mark.anyio
class TestPostLookup:

    @pytest.fixture(autouse=True)
    async def cleanup_provider_client(self, provider):
        yield
        await provider.close()

    async def test_post_lookup_calls_safe_request(self, provider):
        mock_response = httpx.Response(status_code=200, json={})
        mock_payload = {"url": "http://test"}
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)) as mock_safe:
            res = await provider._post_lookup(mock_payload)
            assert res == mock_response
            mock_safe.assert_called_once_with(
                method="POST",
                url=provider._endpoint,
                data=mock_payload,
                headers={"Auth-Key": "test_urlhaus_api_key_123"}
            )


# 5. TestParseResponse
class TestParseResponse:

    def test_parse_response_clean(self, provider):
        res = httpx.Response(
            status_code=200,
            json={"query_status": "no_results"},
            headers={"Content-Type": "application/json"}
        )
        analysis = provider.parse_response(res)
        assert isinstance(analysis, URLHausAnalysis)
        assert analysis.query_status == "no_results"

    def test_parse_response_content_type_invalid(self, provider):
        res = httpx.Response(
            status_code=403,
            text="WAF Block",
            headers={"Content-Type": "text/html"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Expected JSON context but received Content-Type" in str(exc_info.value.message)
        assert exc_info.value.status_code == 403

    def test_parse_response_json_decode_error(self, provider):
        res = httpx.Response(
            status_code=200,
            text="{bad_json",
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Failed to parse URLHaus response payload" in str(exc_info.value.message)

    def test_parse_response_validate_payload_raises(self, provider):
        res = httpx.Response(
            status_code=200,
            json={"error": "some_error"},  # missing query_status
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Schema validation failed" in str(exc_info.value.message)


# =========================================================================
# 6. TestValidatePayload
# =========================================================================
class TestValidatePayload:

    def test_validate_payload_success(self, provider):
        provider._validate_payload({"query_status": "ok"})

    def test_validate_payload_not_dict(self, provider):
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload("not_a_dict")
        assert "Invalid JSON payload structure received" in str(exc_info.value.message)
        assert exc_info.value.status_code == 500

    def test_validate_payload_missing_required_field(self, provider):
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload({"url": "http://foo"})
        assert "query_status" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502


# =========================================================================
# 7. TestExtractQueryStatus
# =========================================================================
class TestExtractQueryStatus:

    def test_extract_query_status(self, provider):
        assert provider._extract_query_status({"query_status": "ok"}) == "ok"
        assert provider._extract_query_status({"query_status": "no_results"}) == "no_results"
        assert provider._extract_query_status({}) == "unknown"


# =========================================================================
# 8. TestExtractUrlStatus
# =========================================================================
class TestExtractUrlStatus:

    def test_extract_url_status(self, provider):
        assert provider._extract_url_status({"url_status": "online"}) == "online"
        assert provider._extract_url_status({"url_status": "offline"}) == "offline"
        assert provider._extract_url_status({}) is None


# =========================================================================
# 9. TestExtractThreat
# =========================================================================
class TestExtractThreat:

    def test_extract_threat(self, provider):
        assert provider._extract_threat({"threat": "malware_download"}) == "malware_download"
        assert provider._extract_threat({}) is None


# =========================================================================
# 10. TestExtractTags
# =========================================================================
class TestExtractTags:

    def test_extract_tags(self, provider):
        assert provider._extract_tags({"tags": ["cobalt", "exe"]}) == ["cobalt", "exe"]
        assert provider._extract_tags({"tags": None}) == []
        assert provider._extract_tags({"tags": "not_a_list"}) == []
        assert provider._extract_tags({}) == []


# =========================================================================
# 11. TestExtractReporter
# =========================================================================
class TestExtractReporter:

    def test_extract_reporter(self, provider):
        assert provider._extract_reporter({"reporter": "abuse_ch"}) == "abuse_ch"
        assert provider._extract_reporter({}) is None


# =========================================================================
# 12. TestExtractFirstSeen
# =========================================================================
class TestExtractFirstSeen:

    def test_extract_first_seen_valid_utc(self, provider):
        res = provider._extract_first_seen({"firstseen": "2025-05-01 11:20:30 UTC"})
        assert res == datetime(2025, 5, 1, 11, 20, 30, tzinfo=timezone.utc)

    def test_extract_first_seen_valid_naive(self, provider):
        res = provider._extract_first_seen({"firstseen": "2025-05-01 11:20:30"})
        assert res == datetime(2025, 5, 1, 11, 20, 30, tzinfo=timezone.utc)

    def test_extract_first_seen_empty(self, provider):
        assert provider._extract_first_seen({}) is None
        assert provider._extract_first_seen({"firstseen": None}) is None

    def test_extract_first_seen_invalid_format(self, provider):
        assert provider._extract_first_seen({"firstseen": "invalid_date_format"}) is None


# =========================================================================
# 13. TestExtractPayloads
# =========================================================================
class TestExtractPayloads:

    def test_extract_payloads_valid(self, provider):
        data = {"payloads": [{"md5": "abc"}, {"sha256": "xyz"}]}
        assert provider._extract_payloads(data) == [{"md5": "abc"}, {"sha256": "xyz"}]

    def test_extract_payloads_empty(self, provider):
        assert provider._extract_payloads({}) == []
        assert provider._extract_payloads({"payloads": None}) == []

    def test_extract_payloads_invalid_type(self, provider):
        assert provider._extract_payloads({"payloads": "not_a_list"}) == []
        assert provider._extract_payloads({"payloads": ["string_not_dict"]}) == []

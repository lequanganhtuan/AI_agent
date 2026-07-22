from __future__ import annotations

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.google_safe_browsing_provider import (
    GoogleSafeBrowsingProvider,
)
from src.core.models import GoogleSafeBrowsingAnalysis


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
def provider() -> GoogleSafeBrowsingProvider:
    """Initializes the GoogleSafeBrowsingProvider client in a fixture."""
    with patch("src.analyzers.url.threat_intelligence.provider.google_safe_browsing_provider.settings") as mock_settings:
        mock_settings.google_safe_browsing_api_key = "test_google_api_key_123"
        return GoogleSafeBrowsingProvider()


# =========================================================================
# 1. Initialization
# =========================================================================
class TestInitialization:

    def test_init_success(self):
        """Verify successful initialization with API key configured."""
        with patch("src.analyzers.url.threat_intelligence.provider.google_safe_browsing_provider.settings") as mock_settings:
            mock_settings.google_safe_browsing_api_key = "mock_key_xyz"
            prov = GoogleSafeBrowsingProvider()
            assert prov._api_key == "mock_key_xyz"
            assert prov.PROVIDER_NAME == "GoogleSafeBrowsing"
            assert "safebrowsing.googleapis.com" in prov._base_url
            assert prov._client_id == "ai-threat-intelligence-pipeline"
            assert prov._client_version == "1.0.0"

    def test_init_missing_api_key(self):
        """Verify ValueError is raised when API key is missing or empty."""
        with patch("src.analyzers.url.threat_intelligence.provider.google_safe_browsing_provider.settings") as mock_settings:
            mock_settings.google_safe_browsing_api_key = ""
            with pytest.raises(ValueError) as exc_info:
                GoogleSafeBrowsingProvider()
            assert "GOOGLE_SAFE_BROWSING_API_KEY is not configured in settings" in str(exc_info.value)


# =========================================================================
# 2. lookup()
# =========================================================================
@pytest.mark.anyio
class TestLookup:

    @pytest.fixture(autouse=True)
    async def cleanup_provider_client(self, provider):
        yield
        await provider.close()

    async def test_lookup_clean_success(self, provider, target_input):
        """URL clean (không có matches)"""
        mock_response = httpx.Response(
            status_code=200,
            json={},
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, GoogleSafeBrowsingAnalysis)
            assert res.threat_found is False
            assert res.threat_type is None
            assert res.platform_type is None
            assert res.cache_duration is None

    async def test_lookup_malicious_success(self, provider, target_input):
        """URL malicious (có matches)"""
        mock_payload = {
            "matches": [
                {
                    "threatType": "MALWARE",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "threat": {"url": "https://example.com/malicious-path"},
                    "cacheDuration": "300s"
                }
            ]
        }
        mock_response = httpx.Response(
            status_code=200,
            json=mock_payload,
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, GoogleSafeBrowsingAnalysis)
            assert res.threat_found is True
            assert res.threat_type == "MALWARE"
            assert res.platform_type == "ANY_PLATFORM"
            assert res.cache_duration == "300s"

    async def test_lookup_normalized_url_empty(self, provider):
        """normalized_url rỗng → ValueError"""
        bad_input = ThreatIntelInput(normalized_url="", domain="example.com")
        with pytest.raises(ValueError) as exc_info:
            await provider.lookup(bad_input)
        assert "Target input normalized_url cannot be null or empty" in str(exc_info.value)

    async def test_lookup_post_lookup_raises_provider_error(self, provider, target_input):
        """_post_lookup raise ProviderError → propagate"""
        custom_err = ProviderError(provider="GoogleSafeBrowsing", message="Quota Exceeded", status_code=429)
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=custom_err)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 429
            assert "Quota Exceeded" in str(exc_info.value.message)

    async def test_lookup_post_lookup_raises_exception(self, provider, target_input):
        """_post_lookup raise Exception → wrap thành ProviderError"""
        generic_exc = ValueError("Network breakdown")
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=generic_exc)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 500
            assert "Lookup failed:" in str(exc_info.value.message)
            assert "Network breakdown" in str(exc_info.value.message)


# =========================================================================
# 3. _build_request_payload()
# =========================================================================
class TestBuildRequestPayload:

    def test_build_request_payload_format(self, provider, target_input):
        """Verify format Google API, threatEntries, clientId, threatTypes, etc."""
        payload = provider._build_request_payload(target_input)
        
        # Payload đúng format Google API
        assert isinstance(payload, dict)
        assert "client" in payload
        assert "threatInfo" in payload
        
        # URL được đưa đúng vào threatEntries
        assert payload["threatInfo"]["threatEntries"] == [{"url": target_input.normalized_url}]
        
        # Có đủ clientId, clientVersion
        assert payload["client"]["clientId"] == provider._client_id
        assert payload["client"]["clientVersion"] == provider._client_version
        
        # Có đủ threatTypes
        expected_threat_types = [
            "MALWARE", 
            "SOCIAL_ENGINEERING", 
            "UNWANTED_SOFTWARE", 
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        assert set(payload["threatInfo"]["threatTypes"]) == set(expected_threat_types)
        
        # Có platformTypes
        assert payload["threatInfo"]["platformTypes"] == ["ANY_PLATFORM"]
        
        # Có threatEntryTypes
        assert payload["threatInfo"]["threatEntryTypes"] == ["URL"]


# =========================================================================
# 4. _post_lookup()
# =========================================================================
@pytest.mark.anyio
class TestPostLookup:

    @pytest.fixture(autouse=True)
    async def cleanup_provider_client(self, provider):
        yield
        await provider.close()

    async def test_post_lookup_calls_safe_request(self, provider):
        """Gọi _safe_request đúng: method, url, params, json và trả về đúng response"""
        mock_response = httpx.Response(status_code=200, json={})
        mock_payload = {"test": "payload"}
        
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)) as mock_safe:
            res = await provider._post_lookup(mock_payload)
            assert res == mock_response
            mock_safe.assert_called_once_with(
                method="POST",
                url=provider._base_url,
                params={"key": provider._api_key},
                json=mock_payload
            )


# =========================================================================
# 5. parse_response()
# =========================================================================
class TestParseResponse:

    def test_parse_response_clean(self, provider):
        """URL clean"""
        res = httpx.Response(
            status_code=200,
            json={},
            headers={"Content-Type": "application/json"}
        )
        analysis = provider.parse_response(res)
        assert isinstance(analysis, GoogleSafeBrowsingAnalysis)
        assert analysis.threat_found is False

    def test_parse_response_malicious(self, provider):
        """URL malicious"""
        res = httpx.Response(
            status_code=200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "cacheDuration": "600s"
                    }
                ]
            },
            headers={"Content-Type": "application/json"}
        )
        analysis = provider.parse_response(res)
        assert isinstance(analysis, GoogleSafeBrowsingAnalysis)
        assert analysis.threat_found is True
        assert analysis.threat_type == "SOCIAL_ENGINEERING"
        assert analysis.platform_type == "ANY_PLATFORM"
        assert analysis.cache_duration == "600s"

    def test_parse_response_not_json(self, provider):
        """Content-Type không phải JSON"""
        res = httpx.Response(
            status_code=200,
            text="<html>Not JSON</html>",
            headers={"Content-Type": "text/html"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Expected JSON context but received Content-Type" in str(exc_info.value.message)

    def test_parse_response_json_decode_error(self, provider):
        """JSON decode lỗi"""
        res = httpx.Response(
            status_code=200,
            text="{invalid-json}",
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Failed to parse Google Safe Browsing payload" in str(exc_info.value.message)

    def test_parse_response_validate_payload_raises_provider_error(self, provider):
        """_validate_payload raise ProviderError"""
        res = httpx.Response(
            status_code=200,
            json={"error": {"code": 400, "message": "API key bad"}},
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Google Business Error" in str(exc_info.value.message)

    def test_parse_response_malformed_payload(self, provider):
        """malformed payload"""
        res = httpx.Response(
            status_code=200,
            json={"matches": "not-a-list"},
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Schema validation failed" in str(exc_info.value.message)


# =========================================================================
# 6. _extract_matches()
# =========================================================================
class TestExtractMatches:

    def test_extract_matches_exists(self, provider):
        """Có matches"""
        data = {"matches": [{"threatType": "MALWARE"}]}
        assert provider._extract_matches(data) == [{"threatType": "MALWARE"}]

    def test_extract_matches_empty(self, provider):
        """Không có matches"""
        data = {"matches": []}
        assert provider._extract_matches(data) == []

    def test_extract_matches_none(self, provider):
        """matches = None"""
        data = {"matches": None}
        assert provider._extract_matches(data) == []

    def test_extract_matches_not_list(self, provider):
        """matches không phải list"""
        data = {"matches": "not_a_list"}
        with pytest.raises(ProviderError) as exc_info:
            provider._extract_matches(data)
        assert "matches" in str(exc_info.value.message)
        assert "must be a list structure" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502


# =========================================================================
# 7. _extract_threat_type()
# =========================================================================
class TestExtractThreatType:

    def test_extract_threat_type_empty_list(self, provider):
        """Empty list"""
        assert provider._extract_threat_type([]) is None

    def test_extract_threat_type_valid_dict(self, provider):
        """Dict hợp lệ"""
        assert provider._extract_threat_type([{"threatType": "SOCIAL_ENGINEERING"}]) == "SOCIAL_ENGINEERING"

    def test_extract_threat_type_first_element_not_dict(self, provider):
        """First element không phải dict"""
        assert provider._extract_threat_type(["not_dict"]) is None

    def test_extract_threat_type_missing_key(self, provider):
        """Không có key threatType"""
        assert provider._extract_threat_type([{"other": "value"}]) is None


# =========================================================================
# 8. _extract_platform()
# =========================================================================
class TestExtractPlatform:

    def test_extract_platform_empty_list(self, provider):
        """Empty list"""
        assert provider._extract_platform([]) is None

    def test_extract_platform_valid_dict(self, provider):
        """Dict hợp lệ"""
        assert provider._extract_platform([{"platformType": "WINDOWS"}]) == "WINDOWS"

    def test_extract_platform_first_element_not_dict(self, provider):
        """First element không phải dict"""
        assert provider._extract_platform(["not_dict"]) is None

    def test_extract_platform_missing_key(self, provider):
        """Không có key platformType"""
        assert provider._extract_platform([{"other": "value"}]) is None


# =========================================================================
# 9. _extract_cache_duration()
# =========================================================================
class TestExtractCacheDuration:

    def test_extract_cache_duration_empty_list(self, provider):
        """Empty list"""
        assert provider._extract_cache_duration([]) is None

    def test_extract_cache_duration_valid_dict(self, provider):
        """Dict hợp lệ"""
        assert provider._extract_cache_duration([{"cacheDuration": "300s"}]) == "300s"

    def test_extract_cache_duration_first_element_not_dict(self, provider):
        """First element không phải dict"""
        assert provider._extract_cache_duration(["not_dict"]) is None

    def test_extract_cache_duration_missing_key(self, provider):
        """Không có key cacheDuration"""
        assert provider._extract_cache_duration([{"other": "value"}]) is None


# =========================================================================
# 10. _first_match()
# =========================================================================
class TestFirstMatch:

    def test_first_match_empty_list(self, provider):
        """Empty list"""
        assert provider._first_match([]) is None

    def test_first_match_element_is_dict(self, provider):
        """First element là dict"""
        assert provider._first_match([{"foo": "bar"}, {"bin": "baz"}]) == {"foo": "bar"}

    def test_first_match_element_not_dict(self, provider):
        """First element không phải dict"""
        assert provider._first_match(["string", {"foo": "bar"}]) is None


# =========================================================================
# 11. _validate_payload()
# =========================================================================
class TestValidatePayload:

    def test_validate_payload_clean(self, provider):
        """Payload sạch"""
        provider._validate_payload({})

    def test_validate_payload_only_matches(self, provider):
        """Payload chỉ có matches"""
        provider._validate_payload({"matches": []})

    def test_validate_payload_empty_dict(self, provider):
        """Payload rỗng {}"""
        provider._validate_payload({})

    def test_validate_payload_not_dict(self, provider):
        """Payload không phải dict"""
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload("string")
        assert "Invalid JSON payload structure received" in str(exc_info.value.message)
        assert exc_info.value.status_code == 500

    def test_validate_payload_error_not_dict(self, provider):
        """error không phải dict"""
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload({"error": "not_dict"})
        assert "Invalid Google Business Error Block format" in str(exc_info.value.message)
        assert exc_info.value.status_code == 500

    def test_validate_payload_business_error(self, provider):
        """Google Business Error"""
        data = {
            "error": {
                "code": 403,
                "message": "The API key is invalid",
                "status": "INVALID_ARGUMENT"
            }
        }
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload(data)
        assert "Google Business Error [INVALID_ARGUMENT]: The API key is invalid" in str(exc_info.value.message)
        assert exc_info.value.status_code == 403

    def test_validate_payload_matches_not_list(self, provider):
        """matches không phải list"""
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload({"matches": "string"})
        assert "Schema validation failed" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502

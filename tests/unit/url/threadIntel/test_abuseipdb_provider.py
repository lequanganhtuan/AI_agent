from __future__ import annotations

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.abuseipdb_provider import (
    AbuseIPDBProvider,
)
from src.core.models import AbuseIPDBAnalysis


# =========================================================================
# FIXTURES
# =========================================================================

@pytest.fixture
def target_input() -> ThreatIntelInput:
    """Provides a normalized DTO for coordinating lookups."""
    return ThreatIntelInput(
        normalized_url="https://example.com/path",
        domain="example.com",
        ip_address="8.8.8.8",
    )


@pytest.fixture
def provider() -> AbuseIPDBProvider:
    """Initializes the AbuseIPDBProvider client in a fixture with a mock API key."""
    with patch("src.analyzers.url.threat_intelligence.provider.abuseipdb_provider.settings") as mock_settings:
        mock_settings.abuseipdb_api_key = "test_abuseipdb_key_123"
        return AbuseIPDBProvider()


# =========================================================================
# 1. Initialization
# =========================================================================
class TestInitialization:

    def test_init_success(self):
        """Verify successful initialization with API key configured."""
        with patch("src.analyzers.url.threat_intelligence.provider.abuseipdb_provider.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = "mock_key_xyz"
            prov = AbuseIPDBProvider()
            assert prov._api_key == "mock_key_xyz"
            assert prov._mock_mode is False
            assert prov.PROVIDER_NAME == "AbuseIPDB"

    def test_init_missing_api_key_mock_mode(self):
        """Verify mock mode is enabled when API key is missing."""
        with patch("src.analyzers.url.threat_intelligence.provider.abuseipdb_provider.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            prov = AbuseIPDBProvider()
            assert prov._api_key is None
            assert prov._mock_mode is True

    def test_init_missing_base_url(self):
        """Verify ValueError is raised when base url is missing."""
        with patch("src.analyzers.url.threat_intelligence.provider.abuseipdb_provider.settings") as mock_settings, \
             patch("src.analyzers.url.threat_intelligence.config.ThreatIntelConfig.ABUSEIPDB_BASE_URL", ""):
            with pytest.raises(ValueError) as exc_info:
                AbuseIPDBProvider()
            assert "AbuseIPDB base URL configuration is missing" in str(exc_info.value)


# =========================================================================
# 2. TestLookup
# =========================================================================
@pytest.mark.anyio
class TestLookup:

    async def test_lookup_empty_ip(self, provider):
        """Empty or missing IP address yields a default clean model."""
        bad_input = ThreatIntelInput(normalized_url="http://test", domain="test.com", ip_address=None)
        res = await provider.lookup(bad_input)
        assert isinstance(res, AbuseIPDBAnalysis)
        assert res.abuse_score == 0

    async def test_lookup_mock_mode_active(self, provider, target_input):
        """In mock mode, return default clean model without network call."""
        provider._mock_mode = True
        with patch.object(provider, "_fetch_abuseipdb_metadata") as mock_fetch:
            res = await provider.lookup(target_input)
            assert isinstance(res, AbuseIPDBAnalysis)
            assert res.abuse_score == 0
            mock_fetch.assert_not_called()

    async def test_lookup_live_success(self, provider, target_input):
        """In live mode, queries and parses AbuseIPDB data successfully."""
        mock_response = httpx.Response(
            status_code=200,
            json={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 95,
                    "totalReports": 12,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "countryCode": "US",
                    "domain": "google.com"
                }
            },
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_fetch_abuseipdb_metadata", AsyncMock(return_value=mock_response)) as mock_fetch:
            res = await provider.lookup(target_input)
            assert isinstance(res, AbuseIPDBAnalysis)
            assert res.ip_address == "8.8.8.8"
            assert res.abuse_score == 95
            assert res.total_reports == 12
            assert res.usage_type == "Data Center/Web Hosting/Transit"
            assert res.country_code == "US"
            assert res.domain == "google.com"
            mock_fetch.assert_called_once_with("8.8.8.8")

    async def test_lookup_propagates_provider_error(self, provider, target_input):
        """ProviderError propagates directly up the call stack."""
        custom_err = ProviderError("AbuseIPDB", "Quota Exceeded", 429)
        with patch.object(provider, "_fetch_abuseipdb_metadata", AsyncMock(side_effect=custom_err)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 429

    async def test_lookup_wraps_general_exception(self, provider, target_input):
        """Exception wrapped into ProviderError and redacts API key."""
        provider._api_key = "secret_api_key_123"
        generic_exc = ValueError("Network crash with key: secret_api_key_123")
        with patch.object(provider, "_fetch_abuseipdb_metadata", AsyncMock(side_effect=generic_exc)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 500
            assert "secret_api_key_123" not in str(exc_info.value.message)
            assert "REDACTED_API_KEY" in str(exc_info.value.message)


# =========================================================================
# 3. TestParseResponse
# =========================================================================
class TestParseResponse:

    def test_parse_response_success(self, provider):
        """Convert standard HTTP response into domain models successfully."""
        res = httpx.Response(
            status_code=200,
            json={
                "data": {
                    "ipAddress": "1.1.1.1",
                    "abuseConfidenceScore": 85,
                    "totalReports": 5,
                    "usageType": "DNS resolver",
                    "countryCode": "SG",
                    "domain": "cloudflare.com"
                }
            },
            headers={"Content-Type": "application/json"}
        )
        parsed = provider.parse_response(res)
        assert isinstance(parsed, AbuseIPDBAnalysis)
        assert parsed.ip_address == "1.1.1.1"
        assert parsed.abuse_score == 85
        assert parsed.total_reports == 5
        assert parsed.usage_type == "DNS resolver"
        assert parsed.country_code == "SG"
        assert parsed.domain == "cloudflare.com"

    def test_parse_response_serialization_failure(self, provider):
        """Serialization failure wraps exception into ProviderError."""
        res = httpx.Response(
            status_code=200,
            text="{invalid_json",
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert exc_info.value.status_code == 200
        assert exc_info.value.raw_error_type == "SerializationFailure"


# =========================================================================
# 4. TestValidatePayload
# =========================================================================
class TestValidatePayload:

    def test_validate_payload_not_dict(self, provider):
        """Validation fails if response body is not a dict."""
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload("not_a_dict", 200)
        assert exc_info.value.raw_error_type == "UnexpectedSchemaRoot"

    def test_validate_payload_errors_unauthorized(self, provider):
        """Invalid API key status code 401 and AuthenticationFailure."""
        data = {
            "errors": [
                {
                    "detail": "Authentication failed: invalid API key.",
                    "status": 401
                }
            ]
        }
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload(data, 200)
        assert exc_info.value.status_code == 401
        assert exc_info.value.raw_error_type == "AuthenticationFailure"

    def test_validate_payload_errors_quota(self, provider):
        """Quota exceeded status code 429 and RateLimitExceeded."""
        data = {
            "errors": [
                {
                    "detail": "Daily limit exceeded.",
                    "status": 429
                }
            ]
        }
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload(data, 200)
        assert exc_info.value.status_code == 429
        assert exc_info.value.raw_error_type == "RateLimitExceeded"

    def test_validate_payload_errors_invalid_ip(self, provider):
        """Malformed or invalid IP status code 422 and InvalidTargetInput."""
        data = {
            "errors": [
                {
                    "detail": "Invalid IP address.",
                    "status": 422
                }
            ]
        }
        with pytest.raises(ProviderError) as exc_info:
            provider._validate_payload(data, 200)
        assert exc_info.value.status_code == 422
        assert exc_info.value.raw_error_type == "InvalidTargetInput"

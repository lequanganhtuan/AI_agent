from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import httpx
import pytest

from src.analyzers.url.threat_intelligence.provider.base_provider import (
    ProviderError,
    ThreatIntelInput,
)
from src.analyzers.url.threat_intelligence.provider.phishtank_provider import (
    PhishTankProvider,
)
from src.core.models import PhishTankAnalysis


# =========================================================================
# FIXTURES
# =========================================================================

@pytest.fixture
def target_input() -> ThreatIntelInput:
    """Provides a normalized URL input DTO for coordinating lookups."""
    return ThreatIntelInput(
        normalized_url="http://example.com/phish",
        domain="example.com",
    )


@pytest.fixture
def provider() -> PhishTankProvider:
    """Initializes the PhishTankProvider client in a fixture."""
    return PhishTankProvider()


# =========================================================================
# TESTS
# =========================================================================

class TestPhishTankProvider:

    # 1. successful init
    def test_init_success(self, provider):
        assert provider.PROVIDER_NAME == "PhishTank"
        assert "checkurl.phishtank.com" in provider._endpoint
        assert "/checkurl/" in provider._endpoint

    # 2. missing config
    def test_init_missing_config(self):
        with patch("src.analyzers.url.threat_intelligence.provider.phishtank_provider.ThreatIntelConfig") as mock_config:
            mock_config.PHISHTANK_BASE_URL = ""
            mock_config.PHISHTANK_LOOKUP_ENDPOINT = "/checkurl/"
            mock_config.PHISHTANK_TIMEOUT_SECONDS = 5
            with pytest.raises(ValueError) as exc_info:
                PhishTankProvider()
            assert "PhishTank configuration is missing" in str(exc_info.value)

        with patch("src.analyzers.url.threat_intelligence.provider.phishtank_provider.ThreatIntelConfig") as mock_config:
            mock_config.PHISHTANK_BASE_URL = "https://checkurl.phishtank.com"
            mock_config.PHISHTANK_LOOKUP_ENDPOINT = ""
            mock_config.PHISHTANK_TIMEOUT_SECONDS = 5
            with pytest.raises(ValueError) as exc_info:
                PhishTankProvider()
            assert "PhishTank configuration is missing" in str(exc_info.value)

    # 3. build payload
    def test_build_request_payload(self, provider, target_input):
        payload = provider._build_request_payload(target_input)
        assert payload == {
            "url": target_input.normalized_url,
            "format": "json"
        }

    # 4. successful post
    @pytest.mark.anyio
    async def test_post_lookup_success(self, provider):
        mock_response = httpx.Response(status_code=200, json={})
        mock_payload = {"url": "http://test", "format": "json"}
        with patch.object(provider, "_safe_request", AsyncMock(return_value=mock_response)) as mock_safe:
            res = await provider._post_lookup(mock_payload)
            assert res == mock_response
            mock_safe.assert_called_once_with(
                method="POST",
                url=provider._endpoint,
                data=mock_payload
            )
            await provider.close()

    # 5. successful lookup & parse phishing URL
    @pytest.mark.anyio
    async def test_lookup_phishing_url(self, provider, target_input):
        mock_response = httpx.Response(
            status_code=200,
            json={
                "meta": {"status": "success"},
                "results": {
                    "url": "http://example.com/phish",
                    "in_database": True,
                    "phish_id": "123456",
                    "phish_detail_page": "https://www.phishtank.com/phish_detail.php?phish_id=123456",
                    "verified": True,
                    "verified_at": "2026-06-29T10:00:00+00:00",
                    "valid": True
                }
            },
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, PhishTankAnalysis)
            assert res.in_database is True
            assert res.verified is True
            assert res.verified_at == datetime(2026, 6, 29, 10, 0, 0, tzinfo=timezone.utc)
            assert res.phish_detail_url == "https://www.phishtank.com/phish_detail.php?phish_id=123456"
            await provider.close()

    # 6. parse clean URL
    @pytest.mark.anyio
    async def test_lookup_clean_url(self, provider, target_input):
        mock_response = httpx.Response(
            status_code=200,
            json={
                "meta": {"status": "success"},
                "results": {
                    "url": "http://example.com/phish",
                    "in_database": False
                }
            },
            headers={"Content-Type": "application/json"}
        )
        with patch.object(provider, "_post_lookup", AsyncMock(return_value=mock_response)):
            res = await provider.lookup(target_input)
            assert isinstance(res, PhishTankAnalysis)
            assert res.in_database is False
            assert res.verified is False
            assert res.verified_at is None
            assert res.phish_detail_url is None
            await provider.close()

    # 7. empty lookup input
    @pytest.mark.anyio
    async def test_lookup_empty_input(self, provider):
        bad_input = ThreatIntelInput(normalized_url="", domain="example.com")
        with pytest.raises(ValueError) as exc_info:
            await provider.lookup(bad_input)
        assert "Target input normalized_url cannot be null or empty" in str(exc_info.value)
        await provider.close()

    # 8. malformed JSON
    def test_parse_response_malformed_json(self, provider):
        res = httpx.Response(
            status_code=200,
            text="{invalid_json}",
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "Failed to parse PhishTank response payload" in str(exc_info.value.message)

    # 9. invalid schema (results missing or not a dict)
    def test_parse_response_missing_results(self, provider):
        res = httpx.Response(
            status_code=200,
            json={"meta": {"status": "success"}},
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "results" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502

    def test_parse_response_results_not_dict(self, provider):
        res = httpx.Response(
            status_code=200,
            json={"results": "not_a_dict"},
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(ProviderError) as exc_info:
            provider.parse_response(res)
        assert "results" in str(exc_info.value.message)
        assert "must be a dict structure" in str(exc_info.value.message)
        assert exc_info.value.status_code == 502

    # 10. parse datetime
    def test_extract_submission_time_valid(self, provider):
        # standard ISO format with timezone offset
        results = {"verified_at": "2026-06-29T10:00:00+00:00"}
        dt = provider._extract_submission_time(results)
        assert dt == datetime(2026, 6, 29, 10, 0, 0, tzinfo=timezone.utc)

        # UTC format
        results = {"submission_time": "2026-06-29 10:00:00 UTC"}
        dt = provider._extract_submission_time(results)
        assert dt == datetime(2026, 6, 29, 10, 0, 0, tzinfo=timezone.utc)

        # Z suffix
        results = {"verified_at": "2026-06-29T10:00:00Z"}
        dt = provider._extract_submission_time(results)
        assert dt == datetime(2026, 6, 29, 10, 0, 0, tzinfo=timezone.utc)

    # 11. datetime error
    def test_extract_submission_time_invalid(self, provider):
        results = {"verified_at": "invalid_date_format"}
        dt = provider._extract_submission_time(results)
        assert dt is None

        results = {}
        dt = provider._extract_submission_time(results)
        assert dt is None

    # 12. ProviderError passthrough
    @pytest.mark.anyio
    async def test_lookup_provider_error_passthrough(self, provider, target_input):
        custom_err = ProviderError(provider="PhishTank", message="Rate limited", status_code=509)
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=custom_err)):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 509
            assert "Rate limited" in str(exc_info.value.message)
        await provider.close()

    # 13. Exception -> ProviderError
    @pytest.mark.anyio
    async def test_lookup_general_exception_wrapped(self, provider, target_input):
        with patch.object(provider, "_post_lookup", AsyncMock(side_effect=RuntimeError("Connection lost"))):
            with pytest.raises(ProviderError) as exc_info:
                await provider.lookup(target_input)
            assert exc_info.value.status_code == 500
            assert "Lookup failed:" in str(exc_info.value.message)
        await provider.close()

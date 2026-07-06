from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from src.dns.models import DNSResult
from src.core.models import (
    ValidationResult,
    ThreatIntelligenceResult,
    ThreatIntelligenceRisk,
    VirusTotalAnalysis,
    GoogleSafeBrowsingAnalysis,
    URLScanAnalysis,
    AbuseIPDBAnalysis,
    URLHausAnalysis,
    URLComponents,
    URLMetadata,
)
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator


@pytest.fixture
def validation_result() -> ValidationResult:
    return ValidationResult(
        valid=True,
        normalized_url="http://example.com/malicious",
        cache_key="test_cache_key_123",
        components=URLComponents(
            scheme="http",
            subdomain="",
            domain="example",
            tld="com",
            path="/malicious",
            params={},
            full_domain="example.com"
        ),
        metadata=URLMetadata(is_ip=False)
    )


@pytest.fixture
def orchestrator() -> ThreatIntelOrchestrator:
    with patch("src.analyzers.url.threat_intelligence.orchestrator.settings") as mock_settings, \
         patch("src.analyzers.url.threat_intelligence.orchestrator.aioredis.Redis.from_url") as mock_redis:
        mock_settings.redis_url = "redis://localhost:6379"
        mock_client = MagicMock()
        mock_redis.return_value = mock_client
        return ThreatIntelOrchestrator()


@pytest.mark.anyio
class TestThreatIntelOrchestrator:

    async def test_orchestrator_cache_hit(self, orchestrator, validation_result):
        """Orchestrator returns full ThreatIntelligenceResult immediately on cache hit."""
        dummy_result = ThreatIntelligenceResult(
            virustotal=VirusTotalAnalysis(),
            google_safe_browsing=GoogleSafeBrowsingAnalysis(),
            urlscan=URLScanAnalysis(),
            ip_reputation=AbuseIPDBAnalysis(),
            urlhaus=URLHausAnalysis(query_status="no_match"),
            risk=ThreatIntelligenceRisk(score=10, risk_level="low")
        )
        
        # Serialize model output
        serialized = dummy_result.model_dump_json().encode("utf-8")
        
        with patch.object(orchestrator._redis_client, "get", AsyncMock(return_value=serialized)) as mock_get, \
             patch.object(orchestrator, "_run_providers_parallel") as mock_run:
            
            res = await orchestrator.analyze_url(validation_result)
            assert isinstance(res, ThreatIntelligenceResult)
            assert res.risk.score == 10
            mock_get.assert_called_once()
            mock_run.assert_not_called()

    async def test_orchestrator_dns_resolution_triggered(self, orchestrator, validation_result):
        """DNSResolver is invoked if the IP is missing in metadata."""
        validation_result.metadata = URLMetadata(is_ip=False)  # Trigger DNS lookup
        
        mock_dns = DNSResult(domain="example.com", ips=["8.8.8.8"], resolved=True)
        
        with patch.object(orchestrator._redis_client, "get", AsyncMock(return_value=None)), \
             patch.object(orchestrator.dns_resolver, "resolve", AsyncMock(return_value=mock_dns)) as mock_dns_resolve, \
             patch.object(orchestrator, "_run_providers_parallel", AsyncMock(return_value=({
                 "virustotal": VirusTotalAnalysis(),
                 "google_safe_browsing": GoogleSafeBrowsingAnalysis(),
                 "urlscan": URLScanAnalysis(),
                 "ip_reputation": AbuseIPDBAnalysis(),
                 "urlhaus": URLHausAnalysis(query_status="no_match"),
             }, 1.0))):
            
            await orchestrator.analyze_url(validation_result)
            mock_dns_resolve.assert_called_once_with("example.com")

    async def test_orchestrator_parallel_execution_and_caching(self, orchestrator, validation_result):
        """Orchestrator gathers results in parallel and caches the result on success."""
        provider_returns = {
            "virustotal": VirusTotalAnalysis(malicious=3, total_engines=50),  # Vt hit
            "google_safe_browsing": GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="MALWARE"), # Gsb hit
            "urlscan": URLScanAnalysis(),
            "urlhaus": URLHausAnalysis(query_status="no_match"),
            "ip_reputation": AbuseIPDBAnalysis(),
        }

        with patch.object(orchestrator._redis_client, "get", AsyncMock(return_value=None)), \
             patch.object(orchestrator, "_run_providers_parallel", AsyncMock(return_value=(provider_returns, 1.0))), \
             patch.object(orchestrator._redis_client, "set", AsyncMock()) as mock_set:
            
            res = await orchestrator.analyze_url(validation_result)
            assert isinstance(res, ThreatIntelligenceResult)
            # Blacklist hits: vt=1, gsb=1 -> BLACKLIST_MATCH triggered -> score = 100
            assert res.risk.score == 100
            assert res.risk.risk_level == "high"
            assert "BLACKLIST_MATCH" in res.risk.triggered_signals
            assert "VT_CONFIRMED_MALICIOUS" in res.risk.triggered_signals
            assert "GOOGLE_BLACKLIST" in res.risk.triggered_signals
            assert res.risk.provider_hits["virustotal"] is True
            assert res.risk.provider_hits["google_safe_browsing"] is True
            assert res.risk.confidence == 1.0

            # Verify saved to cache
            from unittest.mock import ANY
            mock_set.assert_any_call('threat_intelfull_threat_intel:test_cache_key_123', ANY, ex=86400)

    async def test_orchestrator_provider_failure_isolation(self, orchestrator, validation_result):
        """Failures in individual providers do not fail the overall pipeline lookup."""
        # Force a provider lookup exception
        with patch.object(orchestrator.virustotal, "lookup", AsyncMock(side_effect=Exception("API limit exceeded"))), \
             patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=GoogleSafeBrowsingAnalysis())), \
             patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=URLScanAnalysis())), \
             patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
             patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=AbuseIPDBAnalysis())):
             
             with patch.object(orchestrator._redis_client, "get", AsyncMock(return_value=None)):
                  res = await orchestrator.analyze_url(validation_result)
                  # Overall request finishes successfully with fallback VT values
                  assert isinstance(res, ThreatIntelligenceResult)
                  assert res.virustotal.malicious == 0
                  assert res.risk.confidence == 0.8  # 4 out of 5 succeeded

    async def test_orchestrator_phase_3_flow_run(self, orchestrator, validation_result):
        """Verify the full Phase 3 end-to-end execution flow with normalization, scoring, and confidence checks."""
        # 1. Prepare realistic mock responses from each threat intel provider
        mock_vt = VirusTotalAnalysis(malicious=3, total_engines=50)
        mock_gsb = GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="MALWARE")
        mock_urlhaus = URLHausAnalysis(query_status="ok", threat="malware_download")
        mock_urlscan = URLScanAnalysis(malicious_score=85, redirect_count=4)
        mock_ab = AbuseIPDBAnalysis(abuse_score=95, total_reports=12, usage_type="Data Center/Web Hosting")

        # 2. Patch lookups on all 5 engines
        with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=mock_vt)), \
             patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=mock_gsb)), \
             patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=mock_urlscan)), \
             patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=mock_urlhaus)), \
             patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=mock_ab)), \
             patch.object(orchestrator._redis_client, "get", AsyncMock(return_value=None)), \
             patch.object(orchestrator._redis_client, "set", AsyncMock()):

            # 3. Trigger the full Phase 3 execution flow run
            result = await orchestrator.analyze_url(validation_result)

            # 4. Assert correctness of the pipeline integration
            assert isinstance(result, ThreatIntelligenceResult)
            
            # Check risk scoring & thresholds:
            # - Critical Blacklist hits -> Score = 100
            assert result.risk.score == 100
            assert result.risk.risk_level == "high"
            
            # Check triggered signal mapping (Layer 1 normalization)
            assert "BLACKLIST_MATCH" in result.risk.triggered_signals
            assert "VT_CONFIRMED_MALICIOUS" in result.risk.triggered_signals
            assert "GOOGLE_BLACKLIST" in result.risk.triggered_signals
            assert "URLHAUS_INACTIVE_RECORD" in result.risk.triggered_signals
            assert "EXCESSIVE_REDIRECTS" in result.risk.triggered_signals
            assert "ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS" in result.risk.triggered_signals
            assert "ABUSEIPDB_DATACENTER_HOSTING" in result.risk.triggered_signals

            # Check that all providers are correctly registered as hits
            assert result.risk.provider_hits["virustotal"] is True
            assert result.risk.provider_hits["google_safe_browsing"] is True
            assert result.risk.provider_hits["urlhaus"] is True
            assert result.risk.provider_hits["urlscan"] is True
            assert result.risk.provider_hits["ip_reputation"] is True

            # Confidence rate should be 1.0 since all 5 lookup operations completed successfully
            assert result.risk.confidence == 1.0

            # Explanation explanation summary verification (must contain the correct bullet-points)
            assert "✓ VirusTotal detected 3 malicious engines." in result.risk.summary
            assert "✓ Google Safe Browsing identified this URL as MALWARE." in result.risk.summary
            assert "✓ URLHaus reported this URL as malware_download." in result.risk.summary
            assert "✓ URLScan observed malicious behavior." in result.risk.summary
            assert "✓ AbuseIPDB reported an abuse confidence score of 95%." in result.risk.summary

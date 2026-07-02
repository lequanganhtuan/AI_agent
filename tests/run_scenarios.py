import asyncio
import json
import logging
from unittest.mock import AsyncMock, patch

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from src.core.models import (
    GoogleSafeBrowsingAnalysis,
    AbuseIPDBAnalysis,
    URLHausAnalysis,
    URLScanAnalysis,
    VirusTotalAnalysis,
)

# Setup basic logging to console
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ScenarioTester")

async def run_scenario_1_clean():
    """Scenario 1: Clean URL. No engine reports any threats."""
    logger.info("=== RUNNING SCENARIO 1: Clean URL ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://clean-example.com")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # Mock all engines to return completely clean reports
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=VirusTotalAnalysis())), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=GoogleSafeBrowsingAnalysis())), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=URLScanAnalysis())), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=AbuseIPDBAnalysis())):
         
         # Bypass Redis cache get and set
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              assert result.risk.score == 0
              assert result.risk.risk_level == "low"
              assert result.risk.confidence == 1.0

async def run_scenario_2_blacklist():
    """Scenario 2: Blacklist Matches. VirusTotal and Google flag the URL."""
    logger.info("=== RUNNING SCENARIO 2: Blacklist Matches ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://blacklisted-site.net")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # VT flags 4 engines; Google flags MALWARE
    mock_vt = VirusTotalAnalysis(malicious=4, total_engines=65)
    mock_gsb = GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="MALWARE")
    
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=mock_vt)), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=mock_gsb)), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=URLScanAnalysis())), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=AbuseIPDBAnalysis())):
         
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              # Blacklist matches -> score = 40, level = medium
              assert result.risk.score == 40
              assert "VT_CONFIRMED_MALICIOUS" in result.risk.triggered_signals
              assert "GOOGLE_BLACKLIST" in result.risk.triggered_signals

async def run_scenario_3_behavioral():
    """Scenario 3: Behavioral Suspicious Activity. URLScan flags login forms on phishing site."""
    logger.info("=== RUNNING SCENARIO 3: Behavioral Phishing Forms ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("http://fake-banking-login.com")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # URLScan local reasoning flags login fields (form_risk_score = 0.85)
    mock_us = URLScanAnalysis(form_risk_score=0.85, redirect_count=2)
    
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=VirusTotalAnalysis())), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=GoogleSafeBrowsingAnalysis())), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=mock_us)), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=AbuseIPDBAnalysis())):
         
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              # Behavioral risk matched -> score = 25, level = medium
              assert result.risk.score == 25
              assert "PHISHING_FORM_DETECTED" in result.risk.triggered_signals

async def run_scenario_4_reputation():
    """Scenario 4: Reputation Threat. IPQS flags host node as malicious proxy exit node."""
    logger.info("=== RUNNING SCENARIO 4: Reputation Threat ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://proxy-server.info")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # AbuseIPDB flags high abuse score (92) and Datacenter hosting
    mock_ab = AbuseIPDBAnalysis(abuse_score=92, total_reports=12, usage_type="Data Center/Web Hosting")
    
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=VirusTotalAnalysis())), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=GoogleSafeBrowsingAnalysis())), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=URLScanAnalysis())), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=mock_ab)):
         
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              # Reputation risk matched -> score = 15, level = low
              assert result.risk.score == 15
              assert "ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS" in result.risk.triggered_signals
              assert "ABUSEIPDB_DATACENTER_HOSTING" in result.risk.triggered_signals

async def run_scenario_5_partial_failure():
    """Scenario 5: Provider Isolation. VirusTotal fails, but other providers succeed."""
    logger.info("=== RUNNING SCENARIO 5: Provider Lookup Failure Isolation ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://resilient-lookup.org")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # VirusTotal crashes; other engines succeed
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(side_effect=Exception("API connection timeout"))), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=GoogleSafeBrowsingAnalysis())), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=URLScanAnalysis())), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=URLHausAnalysis(query_status="no_match"))), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=AbuseIPDBAnalysis())):
         
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              # Verification: pipeline succeeds; confidence drops to 0.8 (4/5 succeeded)
              assert result.risk.confidence == 0.8
              assert result.risk.provider_hits["virustotal"] is False

async def run_scenario_6_cache_hit():
    """Scenario 6: Cache Hit. Retrieve threat intel results instantly from Redis."""
    logger.info("=== RUNNING SCENARIO 6: Cache Hit ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://cached-malicious-link.net")
    
    orchestrator = ThreatIntelOrchestrator()
    
    # Pre-simulate threat intelligence result dict
    cached_payload = {
        "virustotal": {"malicious": 5, "total_engines": 70},
        "google_safe_browsing": {"threat_found": True, "threat_type": "MALWARE"},
        "urlscan": {"malicious_score": 0},
        "urlhaus": {"query_status": "no_match"},
        "ip_reputation": {"abuse_score": 0},
        "risk": {
            "score": 40,
            "risk_level": "medium",
            "summary": "Retrieved from Cache.\n✓ VirusTotal detected 5 malicious engines.\n✓ Google blacklist matched.",
            "triggered_signals": ["BLACKLIST_MATCH", "VT_CONFIRMED_MALICIOUS", "GOOGLE_BLACKLIST"],
            "provider_hits": {"virustotal": True, "google_safe_browsing": True, "urlhaus": False, "ip_reputation": False, "urlscan": False},
            "confidence": 1.0
        }
    }
    from src.core.models import ThreatIntelligenceResult
    cached_obj = ThreatIntelligenceResult.model_validate(cached_payload)
    # Mock Redis client get to return the cached string
    with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=cached_obj)):
        result = await orchestrator.analyze_url(val_res)
        print(json.dumps(result.risk.model_dump(), indent=2))
        assert result.risk.score == 40
        assert "Retrieved from Cache" in result.risk.summary

async def run_scenario_7_full_compromise():
    """Scenario 7: Combined Threat. All 3 risk buckets trigger, compounding score to maximum."""
    logger.info("=== RUNNING SCENARIO 7: Full Compounded Threat ===")
    url_analyzer = URLAnalyzer()
    val_res = url_analyzer.analyze("https://ultra-threat.cc")
    
    orchestrator = ThreatIntelOrchestrator()
    
    mock_vt = VirusTotalAnalysis(malicious=6)
    mock_gsb = GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="PHISHING")
    mock_urlhaus = URLHausAnalysis(query_status="ok", url_status="online")
    mock_us = URLScanAnalysis(form_risk_score=0.9, redirect_count=4)
    mock_ab = AbuseIPDBAnalysis(abuse_score=98, total_reports=24, usage_type="Data Center/Web Hosting")
    
    with patch.object(orchestrator.virustotal, "lookup", AsyncMock(return_value=mock_vt)), \
         patch.object(orchestrator.google_safe_browsing, "lookup", AsyncMock(return_value=mock_gsb)), \
         patch.object(orchestrator.urlscan, "lookup", AsyncMock(return_value=mock_us)), \
         patch.object(orchestrator.urlhaus, "lookup", AsyncMock(return_value=mock_urlhaus)), \
         patch.object(orchestrator.ip_reputation, "lookup", AsyncMock(return_value=mock_ab)):
         
         with patch.object(orchestrator, "_get_cached_result", AsyncMock(return_value=None)), \
              patch.object(orchestrator, "_cache_result", AsyncMock()):
              
              result = await orchestrator.analyze_url(val_res)
              print(json.dumps(result.risk.model_dump(), indent=2))
              # Blacklist (40) + Behavioral (25) + Reputation (15) = 80
              assert result.risk.score == 80
              assert result.risk.risk_level == "high"
              assert "BLACKLIST_MATCH" in result.risk.triggered_signals
              assert "VT_CONFIRMED_MALICIOUS" in result.risk.triggered_signals
              assert "GOOGLE_BLACKLIST" in result.risk.triggered_signals
              assert "URLHAUS_ACTIVE_MALWARE" in result.risk.triggered_signals
              assert "EXCESSIVE_REDIRECTS" in result.risk.triggered_signals
              assert "ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS" in result.risk.triggered_signals

async def main():
    logger.info("Starting Phase 3 Threat Intel Workflow Scenario Tests...")
    await run_scenario_1_clean()
    await run_scenario_2_blacklist()
    await run_scenario_3_behavioral()
    await run_scenario_4_reputation()
    await run_scenario_5_partial_failure()
    await run_scenario_6_cache_hit()
    await run_scenario_7_full_compromise()
    logger.info("All 7 scenarios successfully tested and verified!")

if __name__ == "__main__":
    asyncio.run(main())

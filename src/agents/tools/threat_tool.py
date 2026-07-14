from typing import Any
from src.agents.state import URLAnalysisState
from src.core.models import (
    ThreatIntelligenceResult, VirusTotalAnalysis, GoogleSafeBrowsingAnalysis,
    URLScanAnalysis, AbuseIPDBAnalysis, ThreatIntelligenceRisk
)
from .base import BaseTool

class ThreatTool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        url = state.analysis.raw_url or ""
        is_malicious = "phishing" in url or "malicious" in url
        
        score = 85 if is_malicious else 0
        level = "high" if is_malicious else "low"
        summary = "Mock high threat detected" if is_malicious else "Mock threat pass"
        
        return ThreatIntelligenceResult(
            virustotal=VirusTotalAnalysis(malicious=5 if is_malicious else 0, found=is_malicious),
            google_safe_browsing=GoogleSafeBrowsingAnalysis(threat_found=is_malicious),
            urlscan=URLScanAnalysis(),
            ip_reputation=AbuseIPDBAnalysis(),
            risk=ThreatIntelligenceRisk(score=score, risk_level=level, summary=summary)
        )

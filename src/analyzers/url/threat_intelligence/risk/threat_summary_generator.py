from __future__ import annotations
from typing import Any
from src.core.models import ThreatSignal
from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig

class ThreatSummaryGenerator:
    """Generator for compiling descriptive security explanation summaries from triggered threat signals."""

    @staticmethod
    def generate(
        signals: list[ThreatSignal],
        provider_data: dict[str, Any],
        blacklist_triggered: bool,
        behavioral_triggered: bool,
        reputation_triggered: bool
    ) -> str:
        summary_parts = []

        # 1. Blacklist summary details
        if blacklist_triggered:
            vt = provider_data.get("virustotal")
            if vt and getattr(vt, "malicious", 0) > 0:
                summary_parts.append(f"VirusTotal detected {vt.malicious} malicious engines.")
            gsb = provider_data.get("google_safe_browsing")
            if gsb and getattr(gsb, "threat_found", False):
                summary_parts.append(f"Google Safe Browsing identified this URL as {gsb.threat_type or 'malicious'}.")
            uh = provider_data.get("urlhaus")
            if uh and getattr(uh, "query_status", None) == "ok":
                summary_parts.append(f"URLHaus reported this URL as {uh.threat or 'malicious'}.")

        # 2. Behavioral summary details
        if behavioral_triggered:
            us = provider_data.get("urlscan")
            if us:
                has_malicious_indicators = any(
                    sig.code in ["BEHAVIORAL_HIGH_RISK", "PHISHING_FORM_DETECTED", "URLSCAN_GLOBAL_MALICIOUS"]
                    for sig in signals
                ) or getattr(us, "malicious_score", 0) >= ThreatIntelConfig.URLSCAN_MALICIOUS_SCORE_THRESHOLD
                
                if has_malicious_indicators:
                    summary_parts.append("URLScan observed malicious behavior.")
                else:
                    summary_parts.append("URLScan observed suspicious behavior.")

        # 3. Reputation summary details
        if reputation_triggered:
            ab = provider_data.get("ip_reputation")
            if ab:
                summary_parts.append(f"AbuseIPDB reported an abuse confidence score of {getattr(ab, 'abuse_score', 0)}%.")

        # Compile final bullet points list
        if not summary_parts:
            return "No security threats or suspicious behaviors were detected."
        else:
            return "\n".join(f"✓ {part}" for part in summary_parts)

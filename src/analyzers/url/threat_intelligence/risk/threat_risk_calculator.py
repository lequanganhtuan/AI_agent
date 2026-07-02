from __future__ import annotations
from typing import Any
from src.core.models import ThreatIntelligenceRisk, ThreatSignal
from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.analyzers.url.threat_intelligence.risk.threat_summary_generator import ThreatSummaryGenerator

class ThreatRiskCalculator:
    """Calculator for aggregating threat telemetry signals into composite risk scores and levels."""

    @staticmethod
    def calculate(
        signals: list[ThreatSignal],
        provider_data: dict[str, Any],
        confidence: float
    ) -> ThreatIntelligenceRisk:
        blacklist_triggered = False
        reputation_triggered = False
        behavioral_triggered = False

        triggered_signals = []
        provider_hits = {
            "virustotal": False,
            "google_safe_browsing": False,
            "urlhaus": False,
            "ip_reputation": False,
            "urlscan": False,
        }

        # Track triggered signals and provider hits
        for sig in signals:
            triggered_signals.append(sig.code)
            
            p_lower = sig.provider.lower()
            if "virustotal" in p_lower:
                provider_hits["virustotal"] = True
            elif "google" in p_lower:
                provider_hits["google_safe_browsing"] = True
            elif "urlhaus" in p_lower:
                provider_hits["urlhaus"] = True
            elif "abuseipdb" in p_lower:
                provider_hits["ip_reputation"] = True
            elif "urlscan" in p_lower:
                provider_hits["urlscan"] = True

            # Categorize triggers
            if sig.code in ["VT_CONFIRMED_MALICIOUS", "VT_SUSPICIOUS", "GOOGLE_BLACKLIST", "URLHAUS_ACTIVE_MALWARE", "URLHAUS_INACTIVE_RECORD"]:
                blacklist_triggered = True
            elif sig.code in ["ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS", "ABUSEIPDB_SUSPICIOUS", "ABUSEIPDB_REPORTS_FOUND", "ABUSEIPDB_DATACENTER_HOSTING"]:
                reputation_triggered = True
            elif sig.code in ["EXCESSIVE_REDIRECTS", "BEHAVIORAL_HIGH_RISK", "BEHAVIORAL_SUSPICIOUS", "PHISHING_FORM_DETECTED", "SUSPICIOUS_LOGIN_FIELDS", "RISKY_ASN_HOSTING", "URLSCAN_GLOBAL_MALICIOUS"]:
                behavioral_triggered = True

        score = 0

        # Calculate composite score from buckets
        if blacklist_triggered:
            score += ThreatIntelConfig.BLACKLIST_SCORE_WEIGHT
            triggered_signals.append("BLACKLIST_MATCH")

        if behavioral_triggered:
            score += ThreatIntelConfig.BEHAVIORAL_SCORE_WEIGHT

        if reputation_triggered:
            score += ThreatIntelConfig.REPUTATION_SCORE_WEIGHT

        # Calculate risk level from final score
        if score >= ThreatIntelConfig.HIGH_RISK_THRESHOLD:
            risk_level = "high"
        elif score >= ThreatIntelConfig.MEDIUM_RISK_THRESHOLD:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Generate summary text using the generator
        summary = ThreatSummaryGenerator.generate(
            signals=signals,
            provider_data=provider_data,
            blacklist_triggered=blacklist_triggered,
            behavioral_triggered=behavioral_triggered,
            reputation_triggered=reputation_triggered
        )

        # Unique and sorted list of triggered signals
        triggered_signals = sorted(list(set(triggered_signals)))

        return ThreatIntelligenceRisk(
            score=score,
            risk_level=risk_level,
            summary=summary,
            triggered_signals=triggered_signals,
            provider_hits=provider_hits,
            confidence=confidence,
        )

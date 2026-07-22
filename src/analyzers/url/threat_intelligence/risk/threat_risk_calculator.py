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

        critical_triggered = []
        high_triggered = []
        medium_triggered = []
        low_triggered = []

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
            if sig.code in ["GOOGLE_BLACKLIST", "URLHAUS_ACTIVE_MALWARE", "VT_CONFIRMED_MALICIOUS", "PHISHING_FORM_DETECTED"]:
                critical_triggered.append(sig.code)
                blacklist_triggered = True
            elif sig.code in ["VT_SUSPICIOUS", "ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS", "BEHAVIORAL_HIGH_RISK", "URLSCAN_GLOBAL_MALICIOUS", "SUSPICIOUS_LOGIN_FIELDS"]:
                high_triggered.append(sig.code)
                if sig.code in ["VT_SUSPICIOUS"]:
                    blacklist_triggered = True
                elif sig.code in ["ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS"]:
                    reputation_triggered = True
                else:
                    behavioral_triggered = True
            elif sig.code in ["ABUSEIPDB_SUSPICIOUS", "ABUSEIPDB_REPORTS_FOUND", "ABUSEIPDB_DATACENTER_HOSTING", "BEHAVIORAL_SUSPICIOUS", "RISKY_ASN_HOSTING", "EXCESSIVE_REDIRECTS"]:
                medium_triggered.append(sig.code)
                if sig.code in ["ABUSEIPDB_SUSPICIOUS", "ABUSEIPDB_REPORTS_FOUND", "ABUSEIPDB_DATACENTER_HOSTING"]:
                    reputation_triggered = True
                else:
                    behavioral_triggered = True
            elif sig.code in ["URLHAUS_INACTIVE_RECORD"]:
                low_triggered.append(sig.code)
                blacklist_triggered = True

        score = 0
        if critical_triggered:
            score = 95 + (len(critical_triggered) - 1) * 5
            triggered_signals.append("BLACKLIST_MATCH")
        elif high_triggered:
            score = 75 + (len(high_triggered) - 1) * 5
            score = min(score, 90)
        elif medium_triggered:
            score = 40 + (len(medium_triggered) - 1) * 5
            score = min(score, 70)
        elif low_triggered:
            score = 15 + (len(low_triggered) - 1) * 2
            score = min(score, 30)

        score = max(0, min(score, 100))

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

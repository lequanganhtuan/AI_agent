from typing import List, Dict
from src.analyzers.url.ai_content_analysis.models import ContentAnalysisResult, AISignal, AISignalType, Severity, FraudCategory
from src.analyzers.url.ai_content_analysis.signal.registry import (
    FRAUD_CATEGORY_SIGNAL_MAP,
    SIGNAL_SEVERITY_MAP,
    KEYWORD_SIGNAL_MAP
)

class AISignalMapper:
    """Core business logic for converting ContentAnalysisResult into a list of unique AISignal objects."""

    def _get_description_for_signal(self, result: ContentAnalysisResult, signal_type: AISignalType) -> str:
        """Extracts a matching description directly from reasoning or findings.
        
        Avoids hardcoding custom description strings.
        """
        # Look for matching keywords for this signal type to select the most relevant reasoning/finding
        matching_keywords = [k for k, v in KEYWORD_SIGNAL_MAP.items() if v == signal_type]
        
        # Check reasoning first
        for r in result.reasoning:
            r_lower = r.lower()
            if any(kw in r_lower for kw in matching_keywords):
                return r
                
        # Check findings second
        for f in result.findings:
            f_lower = f.lower()
            if any(kw in f_lower for kw in matching_keywords):
                return f
                
        # Fallback to the first reasoning item
        if result.reasoning:
            return result.reasoning[0]
            
        # Fallback to the first finding item
        if result.findings:
            return result.findings[0]
            
        # Absolute fallback if both lists are completely empty (no custom string)
        return ""

    def map_signals(self, result: ContentAnalysisResult) -> List[AISignal]:
        """Maps ContentAnalysisResult fields into a list of standardized AISignal objects.
        
        Ensures signal type deduplication.
        """
        signals_by_type: Dict[AISignalType, AISignal] = {}

        # ─── Rule 1: Fraud Category Mapping ──────────────────────────────────
        if result.fraud_category in FRAUD_CATEGORY_SIGNAL_MAP:
            sig_type, severity = FRAUD_CATEGORY_SIGNAL_MAP[result.fraud_category]
            desc = self._get_description_for_signal(result, sig_type)
            
            signals_by_type[sig_type] = AISignal(
                signal=sig_type,
                severity=severity,
                confidence=result.confidence,
                description=desc
            )

        # ─── Rule 2: Brand Impersonation ─────────────────────────────────────
        if result.detected_brand is not None and result.detected_brand.strip():
            sig_type = AISignalType.BRAND_IMPERSONATION
            severity = SIGNAL_SEVERITY_MAP[sig_type]
            desc = self._get_description_for_signal(result, sig_type)
            
            # Map brand impersonation if not already present
            if sig_type not in signals_by_type:
                signals_by_type[sig_type] = AISignal(
                    signal=sig_type,
                    severity=severity,
                    confidence=result.confidence,
                    description=desc
                )

        # ─── Rule 3: Keyword Scanning on Findings & Reasoning ───────────────
        # Scan findings
        for finding in result.findings:
            finding_lower = finding.lower()
            for kw, sig_type in KEYWORD_SIGNAL_MAP.items():
                if kw in finding_lower:
                    if sig_type not in signals_by_type:
                        severity = SIGNAL_SEVERITY_MAP[sig_type]
                        signals_by_type[sig_type] = AISignal(
                            signal=sig_type,
                            severity=severity,
                            confidence=result.confidence,
                            description=finding
                        )
                    break

        # Scan reasoning
        for reason in result.reasoning:
            reason_lower = reason.lower()
            for kw, sig_type in KEYWORD_SIGNAL_MAP.items():
                if kw in reason_lower:
                    if sig_type not in signals_by_type:
                        severity = SIGNAL_SEVERITY_MAP[sig_type]
                        signals_by_type[sig_type] = AISignal(
                            signal=sig_type,
                            severity=severity,
                            confidence=result.confidence,
                            description=reason
                        )
                    break

        # Return unique deduplicated list of generated signals
        return list(signals_by_type.values())

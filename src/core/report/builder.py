import uuid
from datetime import datetime, timezone
from typing import Any
from src.core.models import (
    AnalysisContext,
    StaticAnalysisResult,
    ThreatIntelligenceResult,
    VirusTotalAnalysis,
    GoogleSafeBrowsingAnalysis,
    URLScanAnalysis,
    AbuseIPDBAnalysis,
    ThreatIntelligenceRisk,
    LexicalFeatures,
    BrandAnalysis,
    PatternAnalysis,
    TLDAnalysis,
    TyposquattingAnalysis,
    StaticRiskAnalysis
)
from src.core.report.fraud_report import FraudReport, FraudAIAnalysisReport

class ReportBuilder:
    """Builder class responsible for mapping dynamic runtime contexts to clean static FraudReports."""

    @staticmethod
    def build(context: AnalysisContext, report_id: str = None) -> FraudReport:
        """Transforms a runtime AnalysisContext into a clean persistent FraudReport.

        Args:
            context: The runtime context containing raw pipeline details.
            report_id: Optional ID to override auto-generation (useful for reloading).
        """
        doc_id = report_id or str(uuid.uuid4())
        
        val = context.validation
        cache_key = val.cache_key if val else ""
        url = val.normalized_url if val else ""
        normalized_url = url
        
        ai_report = None
        if context.ai:
            ai_report = FraudAIAnalysisReport(
                content=context.ai.content,
                signals=context.ai.signals,
                risk=context.ai.risk,
                error=context.ai.error,
                system_prompt=context.ai.system_prompt,
                user_prompt=context.ai.user_prompt
            )
            
        return FraudReport(
            id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=normalized_url,
            scanned_at=datetime.now(timezone.utc),
            validation=context.validation,
            static=context.static,
            threat_intelligence=context.threat_intelligence,
            dynamic=context.dynamic,
            ai=ai_report
        )

    @staticmethod
    def build_from_state(analysis_state: Any, report_id: str = None) -> FraudReport:
        """Transforms an agent runtime AnalysisState partition into a clean persistent FraudReport.

        Args:
            analysis_state: The AnalysisState instance from the agent state.
            report_id: Optional ID to override auto-generation.
        """
        doc_id = report_id or str(uuid.uuid4())
        
        val = analysis_state.validation
        cache_key = val.cache_key if val else ""
        url = val.normalized_url if val else ""
        normalized_url = url
        
        # Provide fallback if static analysis was bypassed
        static_res = analysis_state.static
        if not static_res:
            static_res = StaticAnalysisResult(
                lexical=LexicalFeatures(
                    url_length=len(analysis_state.raw_url or ""),
                    root_domain_length=0,
                    full_domain_length=0,
                    subdomain_count=0,
                    url_special_char_count=0,
                    digit_ratio_domain=0.0,
                    domain_entropy=0.0,
                    hyphen_count=0,
                    url_depth=0,
                    query_parameter_count=0,
                    max_path_segment_length=0,
                    longest_token_length=0,
                    consecutive_digit_count=0
                ),
                brand=BrandAnalysis(),
                pattern=PatternAnalysis(),
                tld=TLDAnalysis(),
                typosquatting=TyposquattingAnalysis(),
                risk=StaticRiskAnalysis()
            )

        # Provide fallback if threat intel was bypassed
        threat_res = analysis_state.threat_intelligence
        if not threat_res:
            threat_res = ThreatIntelligenceResult(
                virustotal=VirusTotalAnalysis(),
                google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                urlscan=URLScanAnalysis(),
                ip_reputation=AbuseIPDBAnalysis(),
                risk=ThreatIntelligenceRisk()
            )
        
        ai_report = None
        if analysis_state.ai:
            ai_report = FraudAIAnalysisReport(
                content=analysis_state.ai.content,
                signals=analysis_state.ai.signals,
                risk=analysis_state.ai.risk,
                error=getattr(analysis_state.ai, 'error', None),
                system_prompt=analysis_state.ai.system_prompt,
                user_prompt=analysis_state.ai.user_prompt
            )
            
        return FraudReport(
            id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=normalized_url,
            scanned_at=datetime.now(timezone.utc),
            validation=analysis_state.validation,
            static=static_res,
            threat_intelligence=threat_res,
            dynamic=analysis_state.dynamic,
            ai=ai_report
        )

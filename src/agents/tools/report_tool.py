from typing import Any
from src.agents.state import URLAnalysisState
from src.core.report.builder import ReportBuilder
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
from .base import BaseTool

class ReportTool(BaseTool):
    def _execute(self, state: URLAnalysisState) -> Any:
        if state.control.cache_hit and state.report:
            return state.report

        validation = state.analysis.validation
        
        # Provide fallback if static analysis was bypassed (e.g. cache hit)
        static_res = state.analysis.static
        if not static_res:
            static_res = StaticAnalysisResult(
                lexical=LexicalFeatures(
                    url_length=len(state.analysis.raw_url or ""),
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

        # Provide fallback if threat intel was bypassed (e.g. cache hit)
        threat_res = state.analysis.threat_intelligence
        if not threat_res:
            threat_res = ThreatIntelligenceResult(
                virustotal=VirusTotalAnalysis(),
                google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                urlscan=URLScanAnalysis(),
                ip_reputation=AbuseIPDBAnalysis(),
                risk=ThreatIntelligenceRisk()
            )

        context = AnalysisContext(
            validation=validation,
            static=static_res,
            threat_intel=threat_res,
            dynamic=state.analysis.dynamic,
            ai=state.analysis.ai
        )
        return ReportBuilder.build(context)

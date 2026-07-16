import uuid
from datetime import datetime, timezone
from typing import Any
from src.core.models import (
    AnalysisContext,
    StaticAnalysisResult,
    ThreatIntelligenceResult,
    create_default_static_analysis,
    create_default_threat_intelligence
)
from src.core.report.fraud_report import FraudReport, FraudAIAnalysisReport
from src.agents.state.analysis import AnalysisState
from src.analyzers.url.ai_content_analysis.models import (
    ContentAnalysisResult,
    AIRisk,
    FraudCategory,
    RecommendedAction,
    RiskLevel
)

class ReportBuilder:
    """Builder class responsible for mapping dynamic runtime contexts to clean static FraudReports."""

    @staticmethod
    def _build_report(
        doc_id: str,
        cache_key: str,
        url: str,
        normalized_url: str,
        validation: Any,
        static: Any,
        threat_intelligence: Any,
        dynamic: Any,
        ai: Any
    ) -> FraudReport:
        """Shared private builder implementation to construct the final FraudReport."""
        ai_report = None
        if ai:
            ai_report = FraudAIAnalysisReport(
                content=ai.content,
                signals=ai.signals,
                risk=ai.risk,
                error=getattr(ai, 'error', None),
                system_prompt=getattr(ai, 'system_prompt', None),
                user_prompt=getattr(ai, 'user_prompt', None)
            )
            
        from datetime import timedelta
        from src.core.settings import settings
        
        scanned_time = datetime.now(timezone.utc)
        expire_time = scanned_time + timedelta(seconds=settings.firestore_ttl)

        # Resolve 3-category classification
        from urllib.parse import urlparse
        try:
            url_str = url if url.startswith(("http://", "https://")) else f"https://{url}"
            domain_lower = urlparse(url_str).netloc.lower().replace("www.", "")
            parts = domain_lower.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
        except Exception:
            root_domain = ""
            domain_lower = ""

        is_whitelisted = root_domain in settings.whitelist_domains_set or domain_lower in settings.whitelist_domains_set

        if is_whitelisted:
            composite_score = 0
            risk_level = "safe"
            verdict = "ALLOW"
            
            # Populate default whitelisted AI report content
            if not ai_report:
                ai_report = FraudAIAnalysisReport(
                    content=ContentAnalysisResult(
                        website_purpose="Tên miền thuộc danh sách uy tín / Whitelisted domain.",
                        summary="Tên miền nằm trong danh sách uy tín (Whitelist). Không phát hiện nguy cơ.",
                        detected_brand=None,
                        fraud_category=FraudCategory.LEGITIMATE,
                        confidence=1.0,
                        brand_confidence=0.0,
                        recommended_action=RecommendedAction.ALLOW,
                        verdict_confidence=1.0,
                        reasoning=["Whitelisted domain exit."],
                        findings=["Matches global whitelist."]
                    ),
                    risk=AIRisk(score=0.0, level=RiskLevel.LOW, summary="ALLOW")
                )
            else:
                ai_report.risk = AIRisk(score=0.0, level=RiskLevel.LOW, summary="ALLOW")
                if ai_report.content:
                    ai_report.content.recommended_action = RecommendedAction.ALLOW
                    ai_report.content.summary = "Tên miền nằm trong danh sách uy tín (Whitelist). Không phát hiện nguy cơ."
                    ai_report.content.fraud_category = FraudCategory.LEGITIMATE
                    ai_report.content.confidence = 1.0
        else:
            # Calculate composite score (Max-Risk Strategy)
            threat_score = threat_intelligence.risk.score if threat_intelligence and threat_intelligence.risk else 0
            ai_score = ai_report.risk.score if ai_report and ai_report.risk else 0
            static_score = static.risk.score if static and static.risk else 0

            raw_max_score = max(threat_score, ai_score, static_score)
            
            # Check for SUSPICIOUS Category (New or clean but unverified domains)
            if threat_score == 0 and static_score == 0 and ai_score < 20:
                composite_score = 35
                risk_level = "suspicious"
                verdict = "SUSPICIOUS"
                
                warning_msg = "Tên miền này chưa có danh tiếng established. Vui lòng cẩn trọng trước khi chia sẻ thông tin nhạy cảm. (This domain has no established reputation. Please exercise caution before sharing sensitive information.)"
                if not ai_report:
                    ai_report = FraudAIAnalysisReport(
                        content=ContentAnalysisResult(
                            website_purpose="Tên miền chưa có danh tiếng established / New domain.",
                            summary=warning_msg,
                            detected_brand=None,
                            fraud_category=FraudCategory.OTHER,
                            confidence=0.5,
                            brand_confidence=0.0,
                            recommended_action=RecommendedAction.MONITOR,
                            verdict_confidence=0.5,
                            reasoning=["Domain is not whitelisted.", "No malicious signals found in static, threat intelligence or AI content analysis.", "Classified as Suspicious due to lack of established reputation."],
                            findings=["No prior reputation or history found."]
                        ),
                        risk=AIRisk(score=35.0, level=RiskLevel.MEDIUM, summary="SUSPICIOUS")
                    )
                else:
                    ai_report.risk = AIRisk(score=35.0, level=RiskLevel.MEDIUM, summary="SUSPICIOUS")
                    if ai_report.content:
                        ai_report.content.recommended_action = RecommendedAction.MONITOR
                        ai_report.content.summary = warning_msg
                        ai_report.content.fraud_category = FraudCategory.OTHER
            else:
                # Standard WARN / BLOCK Category
                composite_score = max(0, min(100, int(raw_max_score)))
                if composite_score >= 75:
                    risk_level = "critical"
                    verdict = "BLOCK"
                elif composite_score >= 40:
                    risk_level = "high"
                    verdict = "BLOCK"
                elif composite_score >= 20:
                    risk_level = "medium"
                    verdict = "WARN"
                else:
                    risk_level = "low"
                    verdict = "ALLOW"

        return FraudReport(
            id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=normalized_url,
            scanned_at=scanned_time,
            expire_at=expire_time,
            validation=validation,
            static=static,
            threat_intelligence=threat_intelligence,
            dynamic=dynamic,
            ai=ai_report,
            score=composite_score,
            risk_level=risk_level,
            verdict=verdict
        )

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
        
        return ReportBuilder._build_report(
            doc_id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=url,
            validation=context.validation,
            static=context.static,
            threat_intelligence=context.threat_intelligence,
            dynamic=context.dynamic,
            ai=context.ai
        )

    @staticmethod
    def build_from_state(analysis_state: AnalysisState, report_id: str = None) -> FraudReport:
        """Transforms an agent runtime AnalysisState partition into a clean persistent FraudReport.

        Args:
            analysis_state: The AnalysisState instance from the agent state.
            report_id: Optional ID to override auto-generation.
        """
        doc_id = report_id or str(uuid.uuid4())
        val = analysis_state.validation
        cache_key = val.cache_key if val else ""
        url = val.normalized_url if val else ""
        
        # Load or create domain fallback objects outside the builder
        static_res = analysis_state.static or create_default_static_analysis(url)
        threat_res = analysis_state.threat_intelligence or create_default_threat_intelligence()
        
        return ReportBuilder._build_report(
            doc_id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=url,
            validation=analysis_state.validation,
            static=static_res,
            threat_intelligence=threat_res,
            dynamic=analysis_state.dynamic,
            ai=analysis_state.ai
        )

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
            
        return FraudReport(
            id=doc_id,
            cache_key=cache_key,
            url=url,
            normalized_url=normalized_url,
            scanned_at=datetime.now(timezone.utc),
            validation=validation,
            static=static,
            threat_intelligence=threat_intelligence,
            dynamic=dynamic,
            ai=ai_report
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

import uuid
from datetime import datetime, timezone
from src.core.models import AnalysisContext
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
        # Ensure a UUID is generated if not provided
        doc_id = report_id or str(uuid.uuid4())
        
        # Pull required details from context
        val = context.validation
        cache_key = val.cache_key if val else ""
        url = val.normalized_url if val else ""
        normalized_url = url
        
        # Build AI Analysis Report wrapper
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

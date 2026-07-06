from typing import List, Dict, Any, Optional
from src.core.report.fraud_report import FraudReport

class BaseRepository:
    """Abstract Base Class defining the Repository Interface for persisting FraudReports."""

    async def save_report(self, report: FraudReport) -> str:
        raise NotImplementedError

    async def get_recent_reports(
        self,
        limit: int = 20,
        search: Optional[str] = None,
        verdict: Optional[str] = None,
        risk: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    async def get_report_by_id(self, report_id: str) -> Optional[FraudReport]:
        raise NotImplementedError

from typing import Optional
from src.core.report.fraud_report import FraudReport

class BaseCache:
    """Abstract Base Class defining the Async Cache Interface for FraudReports."""

    async def get(self, key: str) -> Optional[FraudReport]:
        raise NotImplementedError

    async def set(self, key: str, report: FraudReport, ttl: int = 86400) -> None:
        raise NotImplementedError

    async def get_all(self) -> list[FraudReport]:
        return []

    async def close(self) -> None:
        pass


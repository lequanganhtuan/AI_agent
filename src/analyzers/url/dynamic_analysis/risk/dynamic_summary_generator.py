from __future__ import annotations
from src.core.models import DynamicRisk

class DynamicSummaryGenerator:
    """Generator to compile a descriptive text summary based on compiled DynamicRisk assessment."""

    @staticmethod
    def generate(risk: DynamicRisk) -> list[str]:
        """
        Compile structured text summary details from the compiled dynamic risk assessment.
        """
        summary_points = []
        summary_points.append(f"Risk Score: {risk.score}")
        summary_points.append(f"Risk Level: {risk.level}")
        if risk.triggered_signals:
            summary_points.append("Reasons:")
            for sig in risk.triggered_signals:
                summary_points.append(f"  - {sig.evidence}")
        return summary_points

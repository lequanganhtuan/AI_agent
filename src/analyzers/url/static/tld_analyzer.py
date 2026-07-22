from src.core.models import (
    ValidationResult,
    TLDAnalysis,
)
# pyrefly: ignore [missing-import]
from src.analyzers.url.static.config import (
    TLDConfig,
)

class TLDAnalyzer:
    def analyze(self, validation_result: ValidationResult) -> TLDAnalysis:
        components = validation_result.components

        if not components:
            raise ValueError(
                "ValidationResult must contain URL components."
            )

        tld = (
            components.tld.lower().strip()
            if components.tld
            else ""
        )


        high_risk_set = {t.lower() for t in TLDConfig.HIGH_RISK_TLDS}
        medium_risk_set = {t.lower() for t in TLDConfig.MEDIUM_RISK_TLDS}
        low_risk_set = {t.lower() for t in TLDConfig.LOW_RISK_TLDS}
        country_set = {t.lower() for t in TLDConfig.COUNTRY_CODE_TLDS}

        is_high = tld in high_risk_set
        is_medium = tld in medium_risk_set
        is_low = tld in low_risk_set
        is_country = tld in country_set

        if is_high:
            risk_level = "high"
            risk_score = TLDConfig.HIGH_RISK_SCORE

        elif is_medium:
            risk_level = "medium"
            risk_score = TLDConfig.MEDIUM_RISK_SCORE

        elif is_low:
            risk_level = "low"
            risk_score = TLDConfig.LOW_RISK_SCORE

        elif is_country:
            risk_level = "country"
            risk_score = TLDConfig.COUNTRY_SCORE

        else:
            risk_level = "unknown"
            risk_score = TLDConfig.UNKNOWN_SCORE

        return TLDAnalysis(
            tld=tld,
            risk_level=risk_level,
            risk_score=risk_score,
            high_risk_tld=is_high,
            medium_risk_tld=is_medium,
            low_risk_tld=is_low,
            country_code_tld=is_country,
        )
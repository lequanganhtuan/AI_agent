from src.core.models import (
    ValidationResult,
    StaticAnalysisResult,
)

from src.analyzers.url.static.lexical_analyzer import (
    LexicalAnalyzer,
)

from src.analyzers.url.static.brand_analyzer import (
    BrandAnalyzer,
)

from src.analyzers.url.static.pattern_analyzer import (
    PatternAnalyzer,
)

from src.analyzers.url.static.tld_analyzer import (
    TLDAnalyzer,
)

from src.analyzers.url.static.typosquatting_analyzer import (
    TyposquattingAnalyzer,
)

from src.analyzers.url.static.static_risk_calculator import (
    StaticRiskCalculator,
)

class StaticURLAnalyzer:
    def __init__(self):
        """
        Initialize the StaticURLAnalyzer with instances of all sub-analyzers.
        """
        self.lexical_analyzer = LexicalAnalyzer()
        self.brand_analyzer = BrandAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.tld_analyzer = TLDAnalyzer()
        self.typosquatting_analyzer = TyposquattingAnalyzer()
        self.risk_calculator = StaticRiskCalculator()

    def analyze(self, validation_result: ValidationResult) -> StaticAnalysisResult:

        if not validation_result.valid:
            raise ValueError(
                "ValidationResult must be valid."
            )
        if not validation_result.components:
            raise ValueError(
                "ValidationResult must contain URL components."
            )

        lexical = self.lexical_analyzer.analyze(validation_result)
        brand = self.brand_analyzer.analyze(validation_result)
        pattern = self.pattern_analyzer.analyze(validation_result)
        tld = self.tld_analyzer.analyze(validation_result)
        typo = self.typosquatting_analyzer.analyze(validation_result)
        risk = self.risk_calculator.calculate(lexical, brand, pattern, tld, typo)

        return StaticAnalysisResult(
            lexical=lexical,
            brand=brand,
            pattern=pattern,
            tld=tld,
            typosquatting=typo,
            risk=risk
        )

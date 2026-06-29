from difflib import SequenceMatcher

from src.core.models import (
    ValidationResult,
    TyposquattingAnalysis,
)
from src.analyzers.url.static.config import (
    TyposquattingConfig,
)

class TyposquattingAnalyzer:
    def analyze(self, validation_result: ValidationResult) -> TyposquattingAnalysis:
        components = validation_result.components
        
        if not components:
            raise ValueError(
                "ValidationResult must contain URL components."
            )
            
        observed_domain = (components.domain or "").lower().strip()
        full_domain = (components.full_domain or "").lower().strip()
        
        if not observed_domain:
            return TyposquattingAnalysis()
            
        homoglyph_detected = self._homoglyph_detected(observed_domain)
        
        best_match = None
        best_score = 0.0
        best_distance = None
        
        brand_domains_clean = {k.lower(): v.lower() for k, v in TyposquattingConfig.BRAND_DOMAINS.items()}
        
        for brand_lower, legitimate_domain in brand_domains_clean.items():
            
            if (observed_domain == brand_lower and(full_domain == legitimate_domain or full_domain.endswith(f".{legitimate_domain}"))):
                continue
                
            distance = self._levenshtein(observed_domain, brand_lower)
            similarity = self._similarity(observed_domain, brand_lower)
            
            if (distance <= TyposquattingConfig.MAX_LEVENSHTEIN_DISTANCE) and (similarity >= TyposquattingConfig.MIN_SIMILARITY_SCORE):
                if similarity > best_score:
                    best_match = (brand_lower, legitimate_domain)
                    best_score = similarity
                    best_distance = distance
                    
        is_suspicious = bool(best_match) or homoglyph_detected
        
        if not is_suspicious:
            return TyposquattingAnalysis()
            
        return TyposquattingAnalysis(
            suspicious=True,
            target_brand=best_match[0] if best_match else None,
            target_domain=best_match[1] if best_match else None,
            similarity_score=round(best_score, 4) if best_match else 0.0,
            levenshtein_distance=best_distance if best_match else None,
            homoglyph_detected=homoglyph_detected,
            keyboard_typo_detected=self._keyboard_typo_detected(
                observed_domain,
                best_match[0] if best_match else ""
            )
        )
        
    @staticmethod
    def _similarity(source: str, target: str) -> float:
        return SequenceMatcher(None, source, target).ratio()
    
    @staticmethod
    def _levenshtein(source: str, target: str) -> int:
        rows = len(source) + 1
        cols = len(target) + 1
        
        matrix = [[0] * cols for _ in range(rows)]
        
        for i in range(rows):
            matrix[i][0] = i
        for j in range(cols):
            matrix[0][j] = j
            
        for i in range(1, rows):
            for j in range(1, cols):
                cost = (0 if source[i - 1] == target[j - 1] else 1)
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                )
        return matrix[-1][-1]
    
    @staticmethod
    def _homoglyph_detected(domain: str) -> bool:
        suspicious_set = {c.lower() for c in TyposquattingConfig.SUSPICIOUS_CHARS}
        return any(char in suspicious_set for char in domain)
        
    @staticmethod
    def _keyboard_typo_detected(observed: str,brand: str) -> bool:
        if not brand:
            return False

        distance = TyposquattingAnalyzer._levenshtein(
            observed,
            brand,
        )

        return 1 <= distance <= 2
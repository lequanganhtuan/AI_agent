import re
from urllib.parse import urlparse

from src.core.models import (
    ValidationResult,
    PatternAnalysis,
)
from src.analyzers.url.static.config import (
    PatternConfig,
)

class PatternAnalyzer:
    ENCODED_CHARACTER_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
    TOKEN_SPLIT_REGEX = re.compile(r"[^a-z0-9]+")

    def analyze(self, validation_result: ValidationResult) -> PatternAnalysis:
        components = validation_result.components

        if not components:
            raise ValueError("ValidationResult must contain URL components.")

        url = (validation_result.normalized_url or "").lower()
        full_domain = components.full_domain.lower()
        path = components.path.lower()
        parsed = urlparse(url)

        suspicious_keywords = self._detect_suspicious_keywords(
            full_domain=full_domain,
            path=path,
            query=parsed.query.lower()
        )

        encoded_character_count = self._encoded_character_count(url)

        return PatternAnalysis(
            suspicious_keywords=suspicious_keywords,
            suspicious_keyword_count=len(suspicious_keywords),
            encoded_character_detected=encoded_character_count > 0,
            encoded_character_count=encoded_character_count,
            double_extension_detected=self._double_extension_detected(path),
            suspicious_file_extension=self._suspicious_file_extension(path),
            ip_address_url=self._ip_address_url(validation_result),
            url_shortener_detected=self._url_shortener_detected(full_domain),
        )

    def _detect_suspicious_keywords(self, full_domain: str, path: str, query: str) -> list[str]:
        text = f"{full_domain} {path} {query}"
        tokens = self._tokenize(text)
        
        config_keywords = {kw.lower() for kw in PatternConfig.SUSPICIOUS_KEYWORDS}
        matches = tokens.intersection(config_keywords)
        
        return sorted(list(matches))

    @classmethod
    def _tokenize(cls, text: str) -> set[str]:
        return {token for token in cls.TOKEN_SPLIT_REGEX.split(text.lower()) if token}

    @classmethod
    def _encoded_character_count(cls, url: str) -> int:
        return len(cls.ENCODED_CHARACTER_REGEX.findall(url))

    @staticmethod
    def _double_extension_detected(path: str) -> bool:
        if not path:
            return False
        filename = path.split("/")[-1].lower()
        parts = filename.split(".")
        if len(parts) >= 3:
            last_ext = f".{parts[-1]}"
            if last_ext in PatternConfig.SUSPICIOUS_FILE_EXTENSIONS and f".{parts[-2]}" in PatternConfig.CLEAN_EXTENSIONS:
                return True
        return False

    @staticmethod
    def _suspicious_file_extension(path: str) -> bool:
        if not path:
            return False
        filename = path.split("/")[-1]
        for extension in PatternConfig.SUSPICIOUS_FILE_EXTENSIONS:
            if filename.endswith(extension.lower()):
                return True
        return False

    @staticmethod
    def _ip_address_url(validation_result: ValidationResult) -> bool:
        metadata = validation_result.metadata
        return metadata.is_ip if metadata else False

    @staticmethod
    def _url_shortener_detected(full_domain: str) -> bool:
        shorteners_lower = {s.lower() for s in PatternConfig.URL_SHORTENERS}
        for shortener in shorteners_lower:
            if (
                full_domain == shortener
                or
                full_domain.endswith(f".{shortener}")
            ):
                return True

        return False
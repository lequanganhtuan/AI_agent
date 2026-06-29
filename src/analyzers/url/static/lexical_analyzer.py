from collections import Counter
from math import log2
from urllib.parse import urlparse

from src.core.models import (
    ValidationResult,
    LexicalFeatures,
)

from src.analyzers.url.static.config import StaticConfig


class LexicalAnalyzer:
    SPECIAL_CHARS = StaticConfig.SPECIAL_CHARS

    def analyze(self,validation_result: ValidationResult) -> LexicalFeatures:
        url = validation_result.normalized_url
        components = validation_result.components

        if not url or not components:
            raise ValueError(
                "ValidationResult must contain normalized_url and components."
            )

        parsed = urlparse(url)
        root_domain = components.domain
        full_domain = components.full_domain

        return LexicalFeatures(
            # URL Length Metrics
            url_length=self._url_length(url),
            root_domain_length=self._domain_length(root_domain),
            full_domain_length=self._domain_length(full_domain),

            # Domain Structure Metrics
            subdomain_count=self._subdomain_count(components.subdomain),

            # Character-based Features
            url_special_char_count=self._special_char_count(url),
            digit_ratio_domain=self._digit_ratio(full_domain),
            domain_entropy=self._entropy(full_domain),
            hyphen_count=self._hyphen_count(full_domain),

            # Path and Query Features
            url_depth=self._url_depth(parsed.path),
            query_parameter_count=len(components.params),

            # Token-based Features
            max_path_segment_length=(
                self._max_path_segment_length(parsed.path)
            ),
            longest_token_length=(
                self._longest_token_length(full_domain)
            ),
            consecutive_digit_count=(
                self._consecutive_digit_count(full_domain)
            ),
        )

    @staticmethod
    def _url_length(url: str) -> int:
        return len(url)

    @staticmethod
    def _domain_length(domain: str) -> int:
        return len(domain)

    @staticmethod
    def _subdomain_count(subdomain: str) -> int:
        if not subdomain:
            return 0
        return len([part for part in subdomain.split(".") if part])

    def _special_char_count(self,text: str) -> int:
        return sum(1 for char in text if char in self.SPECIAL_CHARS)

    @staticmethod
    def _digit_ratio(domain: str) -> float:
        if not domain:
            return 0.0
        digit_count = sum(1 for char in domain if char.isdigit())
        return round(digit_count / len(domain),4)

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        probabilities = [count / len(text) for count in counts.values()]
        entropy = -sum(p * log2(p) for p in probabilities)

        return round(entropy,4)

    @staticmethod
    def _hyphen_count(domain: str) -> int:
        return domain.count("-")

    @staticmethod
    def _url_depth(path: str) -> int:
        segments = [segment for segment in path.split("/") if segment]
        return len(segments)

    @staticmethod
    def _max_path_segment_length(path: str) -> int:
        segments = [segment for segment in path.split("/") if segment]
        if not segments:
            return 0
        return max( len(segment) for segment in segments)

    @staticmethod
    def _longest_token_length(domain: str) -> int:
        tokens = []
        for token in domain.split("."):
            tokens.extend(token.split("-"))
        if not tokens:
            return 0

        return max(len(token) for token in tokens)

    @staticmethod
    def _consecutive_digit_count(domain: str) -> int:
        max_digits = 0
        current_digits = 0

        for char in domain:
            if char.isdigit():
                current_digits += 1
                max_digits = max(max_digits, current_digits,)
            else:
                current_digits = 0
        return max_digits
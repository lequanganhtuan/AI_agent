import tldextract
from urllib.parse import (
    urlparse,
    parse_qs,
)

from src.core.models import (
    ValidationResult,
    URLComponents,
)

from src.analyzers.url.preprocessing.validator import URLValidator
from src.core.exceptions import URLValidationException

from src.analyzers.url.preprocessing.normalizer import (
    URLNormalizer,
)

from src.analyzers.url.preprocessing.signal_extractor import (
    URLSignalExtractor,
)


class URLAnalyzer():
    
    def __init__(self):
        self.validator = URLValidator()
        self.normalizer = URLNormalizer()
        self.signal_extractor = URLSignalExtractor()
        
    def analyze(self, url: str) -> ValidationResult:
        """
        The main orchestrator method that coordinates the entire URL lifecycle:
        Validation -> Normalization -> Feature Extraction -> Output Compilation.
        """
        try:
            # Preprocess URL to automatically prepend a scheme if missing
            url = url.strip()
            if url and "://" not in url:
                url = f"http://{url}"

            # Run core structural and constraint checks
            self.validator.validate(url)
            # Clean and sanitize the URL string
            normalized_url = self.normalizer.normalize(url)
            # Generate a unique fixed-length ID for caching purposes
            cache_key = self.normalizer.build_cache_key(normalized_url)
            # Scan for security threat signals and collect metadata
            signals, metadata = (self.signal_extractor.extract(normalized_url))
            # Break down the structural anatomy of the URL
            components = self._build_components(normalized_url)
            # Package everything into a successful summary sheet
            return ValidationResult(
                valid=True,
                normalized_url=normalized_url,
                cache_key=cache_key,
                components=components,
                signals=signals,
                metadata=metadata, 
            )
    
        except URLValidationException as exc:
            # If any check fails, immediately stop and return a failure summary sheet
            return ValidationResult(
                valid=False,
                error_code=exc.code.value,
                error_message=exc.message
            )
            
    def _build_components(self, normalized_url: str) -> URLComponents:
        """
        Helper method to slice and dice the domain into TLD, Domain, and Subdomain parts.
        """
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
            
        ext = tldextract.extract(normalized_url)
        
        # Map the safely extracted parts to the corresponding variables
        tld = ext.suffix
        domain = ext.domain
        subdomain = ext.subdomain
        
        # Map out the finalized URLComponents Pydantic model
        return URLComponents(
            scheme=parsed.scheme,
            subdomain=subdomain,
            domain=domain,
            tld=tld,
            path=parsed.path,
            params=parse_qs(parsed.query),
            full_domain=hostname,
        ) 
        

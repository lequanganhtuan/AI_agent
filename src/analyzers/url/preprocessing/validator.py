import ipaddress
import tldextract
from urllib.parse import urlparse
from src.core.enums import ValidationErrorCode
from src.core.exceptions import URLValidationException
from src.analyzers.url.preprocessing.config import URLAnalyzerConfig

class URLValidator():
    # Define constants for validation limits and rules
    MAX_URL_LENGTH = URLAnalyzerConfig.MAX_URL_LENGTH
    OFFICIAL_ALLOWED_SCHEMES = URLAnalyzerConfig.OFFICIAL_ALLOWED_SCHEMES
    
    # Configured dynamic set for suspicious TLDs
    SUSPICIOUS_TLDS = URLAnalyzerConfig.SUSPICIOUS_TLDS
    BLOCKED_METADATA_IPS = URLAnalyzerConfig.BLOCKED_METADATA_IPS

    def validate(self, url: str) -> None:
        """
            Main method to run all URL validation checks.
            Raises URLValidationException if any check fails.
        """
        self._validate_length(url)
        parsed = self._validate_format(url)
        self._validate_scheme(parsed)
        self._validate_infrastructure_safety(parsed)
        
    def _validate_format(self, url: str):
        """Checks if the URL has a correct structural format."""
        parsed = urlparse(url) # Break the URL into 6 components (scheme, netloc, path, etc.)
        
        # A valid URL must have both a scheme (e.g., 'https') and a domain (e.g., 'google.com')
        if not parsed.scheme or not parsed.netloc:
            raise URLValidationException(
                ValidationErrorCode.INVALID_URL_FORMAT,
                "Invalid URL Format"
            )
        
        # Check if netloc is a raw or smart IP address.
        is_raw_ip = False
        try:
            hostname = parsed.hostname or ""
            ipaddress.ip_address(hostname)
            is_raw_ip = True
        except ValueError:
            pass
        
        
        # Use tldextract to prevent errors in extracting complex domains (.com.vn).
        if not is_raw_ip:
            ext = tldextract.extract(url)
            if not ext.domain or not ext.suffix:
                if parsed.scheme.lower() not in {"mailto", "tel", "urn"}:
                    raise URLValidationException(
                        ValidationErrorCode.INVALID_URL_FORMAT,
                        "Invalid domain or extension structure"
                    )
                
        return parsed
        
            
    def _validate_scheme(self, parsed):
        """Checks if the URL protocol/scheme is allowed."""
        # Convert scheme to lowercase to make the check case-insensitive
        if parsed.scheme.lower() not in self.OFFICIAL_ALLOWED_SCHEMES:
            raise URLValidationException(
                ValidationErrorCode.INVALID_SCHEME,
                f"Scheme '{parsed.scheme}' is not allowed'"
            )
            
    def _validate_length(self, url: str):
        """Checks if the URL length exceeds the maximum allowed limit."""
        if len(url) > self.MAX_URL_LENGTH:
            raise URLValidationException(
                ValidationErrorCode.URL_TOO_LONG,
                "URL exceeds maximum length"
            )
        
    def _validate_infrastructure_safety(self, parsed) -> None:
        """Filters out dangerous hostnames and raw IPs to eliminate server-side security flaws (SSRF)."""
        hostname = parsed.hostname or ""
        
        # TODO:
        # Resolve hostname to IP and re-check SSRF ranges
        
        # Block strict string matches against Cloud Metadata APIs
        if hostname in self.BLOCKED_METADATA_IPS:
            raise URLValidationException(
                ValidationErrorCode.SSRF_ATTEMPT,
                "Access to cloud infrastructure metadata endpoints is restricted."
            )

        # Deep packet-level checking if the user passed a raw IP address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            
            # ip_obj.is_private: Covers IPv4 internal scopes & IPv6 Unique Local Address
            # ip_obj.is_loopback: Covers IPv4 localhost (127.0.0.1) & IPv6 Loopback (::1)
            # ip_obj.is_link_local: Covers auto-configured scopes like IPv6 (fe80::/10)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified:
                raise URLValidationException(
                    ValidationErrorCode.SSRF_ATTEMPT,
                    "Targeting private, local loopback, or link-local network interfaces is prohibited."
                )
        except ValueError:
            # Safe to pass if hostname is a text domain label (e.g., 'google.com')
            pass
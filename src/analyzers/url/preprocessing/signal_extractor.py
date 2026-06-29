import ipaddress
import idna  
from urllib.parse import urlparse
from src.core.enums import URLSignal
from src.core.models import URLMetadata
from src.analyzers.url.preprocessing.config import URLAnalyzerConfig

class URLSignalExtractor:
    def __init__(self):
        # Dynamically link the config from validator to keep SUSPICIOUS_TLDS synchronized
        self.suspicious_tlds = (
            URLAnalyzerConfig.SUSPICIOUS_TLDS
        )
    
    def extract(self, normalized_url: str) -> tuple[list[str], URLMetadata]:
        """
        Analyzes a normalized URL to detect security warnings (signals) and extract technical metadata.
        """
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
        signals = []
        metadata = URLMetadata() # Initialize a clean metadata object with default False values

        # Check for Raw IP Address and Private IP Targets
        try:
            # Try to parse the hostname as an actual IP address (IPv4 or IPv6)
            ip_obj = ipaddress.ip_address(hostname)
            metadata.is_ip = True
            signals.append(
                URLSignal.RAW_IP_ADDRESS.value
            )
            # Check if the IP belongs to a local/private network (e.g., 192.168.x.x or 10.x.x.x) 
            # prevent SSRF (Server-Side Request Forgery) attacks
            if  ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                metadata.is_private_ip = True
    
                signals.append(
                    URLSignal.PRIVATE_IP_TARGET.value
                )
        except ValueError:
            # the hostname is a text domain (like 'google.com'), not an IP
            pass
        
        # Check for Non-ASCII / Unicode Characters via IDNA
        hostname_lower = hostname.lower()
        has_punycode_prefix = any(part.startswith("xn--") for part in hostname_lower.split("."))
        if has_punycode_prefix:
            # If the domain starts with 'xn--', it is explicitly encoded to hide non-ASCII characters
            metadata.is_punycode = True
            signals.append(URLSignal.PUNYCODE_DOMAIN.value)
        try:
            # Decode the domain to its native visible characters (e.g., 'xn--pple-43d.com' -> 'аррlе.com')
            # If it is already a regular domain, idna.decode will return it as-is
            decoded_hostname = idna.decode(hostname_lower)
            # If the true unmasked characters fail strict ASCII encoding, it contains Unicode
            decoded_hostname.encode("ascii")
        except (idna.IDNAError, UnicodeEncodeError):
            metadata.contains_unicode = True
            
            signals.append(
                URLSignal.UNICODE_DOMAIN.value
            )
            
        # Check for Untrusted Top-Level Domains (TLDs)
        # Split the hostname by dots to isolate the extension
        parts = hostname_lower.split(".")
        
        if len(parts) >= 2:
            tld = parts[-1] # Extract the last element which represents the TLD
            
            # Flag the URL if its extension is found in the suspicious list
            if tld in self.suspicious_tlds:
                signals.append(
                    URLSignal.SUSPICIOUS_TLD.value
                )
            
        # Return both the collected threat signals and the structured metadata object
        return signals, metadata
from __future__ import annotations
import ipaddress
from urllib.parse import urlparse
import tldextract

def get_apex_domain(url: str) -> str:
    """Extract the apex domain of a URL using tldextract."""
    extracted = tldextract.extract(url)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain # e.g. localhost or IP address

def check_ip_attributes(url: str) -> tuple[bool, bool, bool]:
    """Check if the URL host is an IP, localhost, or private IP."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False, False, False

        # Check localhost string names
        if host.lower() in ["localhost", "127.0.0.1", "::1"]:
            return False, True, True  # localhost is private

        try:
            ip = ipaddress.ip_address(host)
            is_ip = True
            is_localhost = ip.is_loopback
            is_private = ip.is_private
            return is_ip, is_localhost, is_private
        except ValueError:
            # Not an IP address
            return False, False, False
    except Exception:
        return False, False, False

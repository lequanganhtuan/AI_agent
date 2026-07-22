from __future__ import annotations
from typing import Any
import urllib.parse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain, check_ip_attributes

class ScriptDetector:
    """Detector for counting script tags and categorizing external script source links."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    def detect(self, soup: BeautifulSoup, page_url: str = "") -> dict[str, Any]:
        scripts = soup.find_all("script")
        inline_script_count = 0
        external_script_count = 0
        external_scripts = []
        
        first_party_scripts = []
        cdn_scripts = []
        unlisted_scripts = []
        ip_scripts = []

        page_apex = get_apex_domain(page_url) if page_url else ""
        try:
            page_parsed = urlparse(page_url) if page_url else None
            page_host = page_parsed.hostname if page_parsed else ""
        except Exception:
            page_host = ""

        for script in scripts:
            src = script.get("src")
            if src:
                external_script_count += 1
                external_scripts.append(src)
                
                # Check absolute vs relative script path
                is_absolute = src.startswith(("http://", "https://", "//"))
                if not is_absolute:
                    first_party_scripts.append(src)
                else:
                    # Resolve to absolute URL if page_url is present
                    abs_src = urllib.parse.urljoin(page_url, src) if page_url else src
                    try:
                        parsed_src = urlparse(abs_src)
                        src_host = parsed_src.hostname or ""
                        src_apex = get_apex_domain(abs_src)
                    except Exception:
                        src_host = ""
                        src_apex = ""
                        
                    # Check first party alignment
                    if page_url and (
                        (src_host and page_host and src_host.lower() == page_host.lower()) or 
                        (src_apex and page_apex and src_apex.lower() == page_apex.lower())
                    ):
                        first_party_scripts.append(src)
                    else:
                        # Check if raw IP script source
                        is_ip, _, _ = check_ip_attributes(abs_src)
                        if is_ip:
                            ip_scripts.append(src)
                        # Check CDN categorization keywords and host lookups
                        elif any(kw in src_host.lower() for kw in self.config.CDN_KEYWORDS) or src_host.lower() in [
                            "cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com", "unpkg.com", "cdn.jsdelivr.net"
                        ]:
                            cdn_scripts.append(src)
                        # Unlisted / unknown domain source
                        else:
                            unlisted_scripts.append(src)
            else:
                inline_script_count += 1
                
        return {
            "inline_script_count": inline_script_count,
            "external_script_count": external_script_count,
            "external_scripts": external_scripts,
            "first_party_scripts": first_party_scripts,
            "cdn_scripts": cdn_scripts,
            "unlisted_scripts": unlisted_scripts,
            "ip_scripts": ip_scripts
        }

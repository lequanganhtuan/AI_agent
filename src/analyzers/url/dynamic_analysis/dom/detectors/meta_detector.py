from __future__ import annotations
from typing import Any
from bs4 import BeautifulSoup

class MetaDetector:
    """Detector for identifying http-equiv refresh redirection meta tags and extracting redirect URLs."""

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        meta_tags = soup.find_all("meta")
        has_meta_refresh = False
        meta_refresh_url = None
        
        for meta in meta_tags:
            http_equiv = (meta.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                has_meta_refresh = True
                content = meta.get("content") or ""
                # Parse url from content, e.g. "5;url=https://example.com"
                if "url=" in content.lower():
                    try:
                        parts = content.split(";", 1)
                        for part in parts:
                            if "url=" in part.lower():
                                url_part = part.split("=", 1)[1].strip()
                                # Clean quotes if present
                                url_part = url_part.strip("'\"")
                                meta_refresh_url = url_part
                                break
                    except Exception:
                        pass
                break
                
        return {
            "has_meta_refresh": has_meta_refresh,
            "meta_refresh_url": meta_refresh_url
        }

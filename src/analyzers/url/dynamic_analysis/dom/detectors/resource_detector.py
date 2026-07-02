from __future__ import annotations
from typing import Any
from bs4 import BeautifulSoup

class ResourceDetector:
    """Detector for identifying page resource assets (image source links and favicon link)."""

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        images = soup.find_all("img")
        image_sources = []
        for img in images:
            src = img.get("src")
            if src:
                image_sources.append(src)
                
        # Favicon parsing
        favicon_url = None
        links = soup.find_all("link")
        for link in links:
            rel = [r.lower() for r in (link.get("rel") or [])]
            if "icon" in rel or "shortcut" in rel or "shortcut icon" in rel:
                favicon_url = link.get("href")
                break
                
        return {
            "image_sources": image_sources,
            "favicon_url": favicon_url
        }

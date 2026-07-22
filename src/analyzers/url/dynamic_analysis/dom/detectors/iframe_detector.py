from __future__ import annotations
from typing import Any
from bs4 import BeautifulSoup

class IframeDetector:
    """Detector for identifying total iframes and hidden/zero-dimensional iframes."""

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        iframes = soup.find_all("iframe")
        iframe_count = len(iframes)
        hidden_iframe_count = 0
        
        for iframe in iframes:
            width = (iframe.get("width") or "").strip().lower()
            height = (iframe.get("height") or "").strip().lower()
            style = (iframe.get("style") or "").strip().lower()
            hidden_attr = iframe.get("hidden") is not None
            
            # Check zero dimensions
            is_zero_size = (width in ["0", "0px"] and height in ["0", "0px"])
            
            # Check hidden styles
            is_style_hidden = (
                "display:none" in style.replace(" ", "") or 
                "display: none" in style or
                "visibility:hidden" in style.replace(" ", "") or
                "visibility: hidden" in style or
                "width:0" in style.replace(" ", "") or
                "width: 0" in style or
                "height:0" in style.replace(" ", "") or
                "height: 0" in style or
                "opacity:0" in style.replace(" ", "") or
                "opacity: 0" in style
            )
            
            if is_zero_size or is_style_hidden or hidden_attr:
                hidden_iframe_count += 1
                
        return {
            "iframe_count": iframe_count,
            "hidden_iframe_count": hidden_iframe_count
        }

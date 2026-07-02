from __future__ import annotations
from typing import Any
from bs4 import BeautifulSoup

class ScriptDetector:
    """Detector for counting script tags and tracking external script source links."""

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        scripts = soup.find_all("script")
        inline_script_count = 0
        external_script_count = 0
        external_scripts = []
        
        for script in scripts:
            src = script.get("src")
            if src:
                external_script_count += 1
                external_scripts.append(src)
            else:
                inline_script_count += 1
                
        return {
            "inline_script_count": inline_script_count,
            "external_script_count": external_script_count,
            "external_scripts": external_scripts
        }

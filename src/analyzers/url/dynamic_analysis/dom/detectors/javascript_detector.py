from __future__ import annotations
import re
from typing import Any
from bs4 import BeautifulSoup

class JavaScriptDetector:
    """Detector for identifying high-risk functions strictly inside inline script tags."""

    def __init__(self) -> None:
        # Pre-compile immutable regex pattern match definitions
        self.eval_pattern = re.compile(r"\beval\s*\(")
        self.atob_pattern = re.compile(r"\batob\s*\(")
        self.unescape_pattern = re.compile(r"\bunescape\s*\(")

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        scripts = soup.find_all("script")
        has_eval = False
        has_atob = False
        has_unescape = False
        
        for script in scripts:
            # Inline script has no src
            if not script.get("src"):
                content = script.string or ""
                if self.eval_pattern.search(content):
                    has_eval = True
                if self.atob_pattern.search(content):
                    has_atob = True
                if self.unescape_pattern.search(content):
                    has_unescape = True
                    
        return {
            "has_eval": has_eval,
            "has_atob": has_atob,
            "has_unescape": has_unescape
        }

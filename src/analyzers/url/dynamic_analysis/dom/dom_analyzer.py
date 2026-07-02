from __future__ import annotations
from bs4 import BeautifulSoup
from src.core.models import PageSnapshot, DOMAnalysis
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.dom.detectors.form_detector import FormDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.iframe_detector import IframeDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.meta_detector import MetaDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.javascript_detector import JavaScriptDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.script_detector import ScriptDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.resource_detector import ResourceDetector

class DOMAnalyzer:
    """Orchestrator for delegating HTML analysis to dedicated structural detectors."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()
        self.form_detector = FormDetector(config=self.config)
        self.iframe_detector = IframeDetector()
        self.meta_detector = MetaDetector()
        self.javascript_detector = JavaScriptDetector()
        self.script_detector = ScriptDetector()
        self.resource_detector = ResourceDetector()

    def analyze(self, snapshot: PageSnapshot) -> DOMAnalysis:
        """
        Parse HTML source from a PageSnapshot and run structural analysis.

        Args:
            snapshot: PageSnapshot containing the raw HTML content.

        Returns:
            DOMAnalysis: Data object containing DOM structure characteristics.
        """
        html_content = snapshot.html or ""
        soup = BeautifulSoup(html_content, "html.parser")

        # Delegate parsing tasks to focused detectors
        form_data = self.form_detector.detect(soup)
        iframe_data = self.iframe_detector.detect(soup)
        meta_data = self.meta_detector.detect(soup)
        js_data = self.javascript_detector.detect(soup)
        script_data = self.script_detector.detect(soup)
        resource_data = self.resource_detector.detect(soup)

        return DOMAnalysis(
            form_count=form_data["form_count"],
            has_login_form=form_data["has_login_form"],
            has_password_field=form_data["has_password_field"],
            has_otp_field=form_data["has_otp_field"],
            has_cccd_field=form_data["has_cccd_field"],
            has_credit_card_field=form_data["has_credit_card_field"],

            iframe_count=iframe_data["iframe_count"],
            hidden_iframe_count=iframe_data["hidden_iframe_count"],

            has_meta_refresh=meta_data["has_meta_refresh"],
            meta_refresh_url=meta_data["meta_refresh_url"],

            has_eval=js_data["has_eval"],
            has_atob=js_data["has_atob"],
            has_unescape=js_data["has_unescape"],

            inline_script_count=script_data["inline_script_count"],
            external_script_count=script_data["external_script_count"],
            external_scripts=script_data["external_scripts"],

            image_sources=resource_data["image_sources"],
            favicon_url=resource_data["favicon_url"]
        )

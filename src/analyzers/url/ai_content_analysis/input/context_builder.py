from typing import Optional
from bs4 import BeautifulSoup

from src.core.models import AnalysisContext
from src.analyzers.url.ai_content_analysis.models import AIAnalysisInput
from src.analyzers.url.ai_content_analysis.input.text_extractor import extract_text
from src.analyzers.url.ai_content_analysis.input.screenshot_encoder import encode_screenshot
from src.analyzers.url.ai_content_analysis.input.metadata_builder import build_metadata

def build_context(context: AnalysisContext, html: Optional[str] = None) -> AIAnalysisInput:
    """Assembles and transforms the raw application context into a streamlined analysis input payload.
    
    Coordinates the execution sequence:
    1. Extract and sanitize HTML to plain text.
    2. Extract and Base64 encode the screenshot.
    3. Construct a minimalist metadata dictionary.
    4. Collect summaries from the static, threat, and dynamic phases.
    5. Deduplicate and filter a flat list of triggered signal names.
    """
    # 1. URL & Final URL
    url = context.validation.normalized_url or ""
    final_url = url
    if context.dynamic and context.dynamic.redirects and context.dynamic.redirects.redirect_chain:
        final_url = context.dynamic.redirects.redirect_chain[-1]

    # 2. Page Title Extraction from HTML
    page_title = ""
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                page_title = title_tag.get_text().strip()
        except Exception:
            pass

    # 3. Clean Plain Text Extraction
    extracted_text = extract_text(html) if html else ""

    # 4. Screenshot Base64 encoding
    screenshot_path = context.dynamic.screenshot_path if context.dynamic else None
    base64_screenshot = encode_screenshot(screenshot_path) if screenshot_path else None

    # 5. Legitimate Domain Target extraction (e.g. typosquatting target)
    legitimate_domain = None
    if context.static and context.static.brand:
        legitimate_domain = context.static.brand.typosquatting_target

    # 6. Aggregate Summaries from previous phases
    static_summary = ""
    if context.static and context.static.risk and context.static.risk.summary:
        static_summary = "\n".join(context.static.risk.summary)

    threat_summary = ""
    if context.threat_intelligence and context.threat_intelligence.risk:
        threat_summary = context.threat_intelligence.risk.summary

    dynamic_summary = ""
    if context.dynamic and context.dynamic.summary:
        dynamic_summary = "\n".join(context.dynamic.summary)

    # 7. Collect and deduplicate signal identifier strings
    signals_set = set()
    if context.validation and context.validation.signals:
        for sig in context.validation.signals:
            signals_set.add(sig)

    if context.static and context.static.risk and context.static.risk.triggered_signals:
        for sig in context.static.risk.triggered_signals:
            signals_set.add(sig)

    if context.threat_intelligence and context.threat_intelligence.risk and context.threat_intelligence.risk.triggered_signals:
        for sig in context.threat_intelligence.risk.triggered_signals:
            signals_set.add(sig)

    if context.dynamic and context.dynamic.signals:
        for sig in context.dynamic.signals:
            signals_set.add(sig.signal)

    important_signals = sorted(list(signals_set))

    # 8. Build lightweight metadata dictionary
    metadata = build_metadata(context, html)

    # 9. Return validated AIAnalysisInput schema object
    return AIAnalysisInput(
        url=url,
        final_url=final_url,
        page_title=page_title,
        extracted_text=extracted_text,
        screenshot_path=base64_screenshot,
        legitimate_domain=legitimate_domain,
        static_summary=static_summary,
        threat_summary=threat_summary,
        dynamic_summary=dynamic_summary,
        important_signals=important_signals,
        metadata=metadata
    )

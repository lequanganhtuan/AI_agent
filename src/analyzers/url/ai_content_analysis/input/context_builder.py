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
    # Extract local bindings to reduce structural coupling
    dynamic = context.dynamic
    static = context.static
    threat = context.threat_intelligence
    validation = context.validation

    # 1. URL & Final URL
    url = validation.normalized_url if validation else ""
    final_url = url
    redirects = dynamic.redirects if dynamic else None
    if redirects and redirects.redirect_chain:
        final_url = redirects.redirect_chain[-1]

    # 2. Page Title Extraction from Phase 4 dynamic context or HTML fallback
    page_title = ""
    dynamic_page = getattr(dynamic, "page", None) if dynamic else None
    if dynamic_page:
        page_title = getattr(dynamic_page, "title", "") or ""

    if not page_title and html:
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
    screenshot_path = dynamic.screenshot_path if dynamic else None
    base64_screenshot = encode_screenshot(screenshot_path) if screenshot_path else None

    # 5. Legitimate Domain Target extraction (e.g. typosquatting target)
    legitimate_domain = None
    brand = static.brand if static else None
    if brand:
        legitimate_domain = brand.typosquatting_target

    # 6. Aggregate Summaries from previous phases
    static_risk = static.risk if static else None
    static_summary = ""
    if static_risk and static_risk.summary:
        static_summary = "\n".join(static_risk.summary)

    threat_risk = threat.risk if threat else None
    threat_summary = ""
    if threat_risk:
        threat_summary = threat_risk.summary

    dynamic_summary = ""
    if dynamic and dynamic.summary:
        dynamic_summary = "\n".join(dynamic.summary)

    # 7. Collect and deduplicate signal identifier strings
    signals_set = set()
    if validation and validation.signals:
        for sig in validation.signals:
            signals_set.add(sig)

    if static_risk and static_risk.triggered_signals:
        for sig in static_risk.triggered_signals:
            signals_set.add(sig)

    if threat_risk and threat_risk.triggered_signals:
        for sig in threat_risk.triggered_signals:
            signals_set.add(sig)

    if dynamic and dynamic.signals:
        for sig in dynamic.signals:
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
        metadata=metadata,
        language=getattr(context, "language", "vi")
    )

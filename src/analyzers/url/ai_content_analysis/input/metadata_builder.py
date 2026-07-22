from typing import Any, Optional
from bs4 import BeautifulSoup
from src.core.models import AnalysisContext

def build_metadata(context: AnalysisContext, html: Optional[str] = None) -> dict[str, Any]:
    """Generates a compact metadata payload containing highly curated features for optimization.
    
    No Object Cloning: Do not duplicate or drop the entire raw DynamicAnalysisResult object.
    Strictly Minimalist: Extract and isolate only a few key, high-signal data points.
    """
    # 1. url_length from validation normalized_url
    url_str = context.validation.normalized_url or ""
    url_length = len(url_str)
    
    # 2. page_language (extract from html tag's lang attribute, default to "en")
    page_language = "en"
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            html_tag = soup.find("html")
            if html_tag:
                lang_attr = html_tag.get("lang")
                if lang_attr:
                    # Isolate language prefix (e.g. "en-US" -> "en")
                    page_language = str(lang_attr).strip().split("-")[0].split("_")[0].lower()
        except Exception:
            pass

    # 3. redirect_count from dynamic redirects analysis
    redirect_count = 0
    if context.dynamic and context.dynamic.redirects:
        redirect_count = context.dynamic.redirects.redirect_count
        
    # 4. Form presence indicators
    has_login_form = False
    has_payment_form = False
    has_otp_form = False
    
    if context.dynamic and context.dynamic.dom:
        dom = context.dynamic.dom
        has_login_form = getattr(dom, "has_login_form", False)
        has_otp_form = getattr(dom, "has_otp_field", False) or getattr(dom, "has_otp_form", False)
        has_payment_form = getattr(dom, "has_credit_card_field", False)

    return {
        "url_length": url_length,
        "page_language": page_language,
        "redirect_count": redirect_count,
        "has_login_form": has_login_form,
        "has_payment_form": has_payment_form,
        "has_otp_form": has_otp_form
    }

import re
import logging

logger = logging.getLogger(__name__)

# Pre-compile regex patterns for performance
RE_SCRIPT = re.compile(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', re.IGNORECASE)
RE_STYLE = re.compile(r'<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>', re.IGNORECASE)
RE_NOSCRIPT = re.compile(r'<noscript\b[^<]*(?:(?!</noscript>)<[^<]*)*</noscript>', re.IGNORECASE)
RE_SVG = re.compile(r'<svg\b[^<]*(?:(?!</svg>)<[^<]*)*</svg>', re.IGNORECASE)
RE_IFRAME = re.compile(r'<iframe\b[^<]*(?:(?!</iframe>)<[^<]*)*</iframe>', re.IGNORECASE)
RE_COMMENTS = re.compile(r'<!--[\s\S]*?-->')
RE_INLINE_DATA_IMG = re.compile(r'src=["\']data:image/[^"\']+["\']', re.IGNORECASE)
RE_ATTRIBUTES = re.compile(r'\s+(class|id|style|data-[a-z0-9_-]+|aria-[a-z0-9_-]+)=["\'][^"\']*["\']', re.IGNORECASE)
RE_MULTIPLE_NEWLINES = re.compile(r'\n\s*\n')
RE_MULTIPLE_SPACES = re.compile(r'[ \t]+')

def clean_html_for_llm(raw_html: str, max_length: int = 15000) -> str:
    """
    Minifies and cleans raw HTML code before sending to LLM.
    Strips scripts, styles, SVGs, base64 images, comments, and redundant inline attributes.
    Reduces token size by 80-95% while keeping semantic structure.
    """
    if not raw_html:
        return ""

    original_len = len(raw_html)
    
    # 1. Remove non-content structural tags
    text = RE_SCRIPT.sub('', raw_html)
    text = RE_STYLE.sub('', text)
    text = RE_NOSCRIPT.sub('', text)
    text = RE_SVG.sub('', text)
    text = RE_IFRAME.sub('', text)
    text = RE_COMMENTS.sub('', text)
    
    # 2. Remove base64 image data strings
    text = RE_INLINE_DATA_IMG.sub('src=""', text)
    
    # 3. Strip non-semantic attributes (class, style, id, data-*, aria-*)
    text = RE_ATTRIBUTES.sub('', text)
    
    # 4. Collapse whitespace
    text = RE_MULTIPLE_SPACES.sub(' ', text)
    text = RE_MULTIPLE_NEWLINES.sub('\n', text)
    text = text.strip()

    cleaned_len = len(text)
    reduction = ((original_len - cleaned_len) / original_len * 100) if original_len > 0 else 0
    logger.info(f"[HTMLCleaner] Raw HTML size: {original_len} chars -> Minified: {cleaned_len} chars ({reduction:.1f}% reduction)")

    # 5. Cap length if exceeding safety limit
    if len(text) > max_length:
        text = text[:max_length] + "\n...[Content truncated for length limit]..."

    return text

import html as html_lib
from bs4 import BeautifulSoup, Comment

def extract_text(html: str) -> str:
    """Accepts a raw HTML string and extracts a sanitized, plain-text string representation.
    
    It removes non-text elements (script, style, noscript, svg, canvas), removes HTML comments,
    decodes HTML entities, and normalizes all whitespaces.
    """
    if not html:
        return ""

    # Parse HTML using BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")

    # Strip HTML comments
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    # Strip structural and executable non-text tags
    for tag in soup(["script", "style", "noscript", "svg", "canvas"]):
        tag.extract()

    # Extract text with separator space to preserve boundaries between tags
    raw_text = soup.get_text(separator=" ")

    # Decode HTML Entities
    decoded_text = html_lib.unescape(raw_text)

    # Normalize whitespace: collapse consecutive spaces, tabs, newlines into a single space
    normalized_text = " ".join(decoded_text.split())

    return normalized_text

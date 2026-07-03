import pytest
from src.analyzers.url.ai_content_analysis.input.text_extractor import extract_text

def test_extract_text_empty():
    assert extract_text("") == ""
    assert extract_text(None) == ""
    assert extract_text("   \n\t   ") == ""

def test_extract_text_strip_non_text_elements():
    html = """
    <html>
        <head>
            <style>body { color: red; }</style>
            <script>console.log("hello");</script>
        </head>
        <body>
            <noscript>JavaScript is disabled</noscript>
            <div>Hello World</div>
            <svg><path d="M0 0h24v24H0z"/></svg>
            <canvas id="myCanvas"></canvas>
        </body>
    </html>
    """
    assert extract_text(html) == "Hello World"

def test_extract_text_strip_comments():
    html = "<div>Hello <!-- this is a comment --> World</div>"
    assert extract_text(html) == "Hello World"

def test_extract_text_decode_entities():
    html = "<div>&amp; &lt; &gt; &quot; &apos;</div>"
    assert extract_text(html) == "& < > \" '"

def test_extract_text_normalize_whitespace():
    html = "<div>hello  \n\n\t  world</div>"
    assert extract_text(html) == "hello world"

def test_extract_text_preserve_visual_order():
    html = """
    <div>First Line</div>
    <p>Second Line</p>
    <span>Third Line</span>
    """
    assert extract_text(html) == "First Line Second Line Third Line"

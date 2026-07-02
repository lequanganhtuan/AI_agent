from __future__ import annotations
import pytest
from src.core.models import PageSnapshot, DOMAnalysis
from src.analyzers.url.dynamic_analysis.dom.dom_analyzer import DOMAnalyzer

def create_snapshot_with_html(html: str) -> PageSnapshot:
    """Helper to instantiate a mock PageSnapshot containing raw HTML."""
    return PageSnapshot(
        original_url="http://test.com",
        final_url="http://test.com",
        status_code=200,
        title="Test Title",
        html=html,
        load_time_ms=100.0,
        redirect_chain=["http://test.com"]
    )

def test_dom_analyzer_empty():
    """Verify default clean extraction on empty HTML content."""
    snapshot = create_snapshot_with_html("")
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert isinstance(result, DOMAnalysis)
    assert result.form_count == 0
    assert result.iframe_count == 0
    assert result.has_login_form is False
    assert result.has_password_field is False
    assert result.has_meta_refresh is False
    assert result.has_eval is False
    assert len(result.external_scripts) == 0
    assert len(result.image_sources) == 0


def test_dom_analyzer_forms():
    """Verify identification of forms and sensitive credential fields (password, CCCD, credit card, OTP)."""
    html = """
    <html>
      <body>
        <form id="login-form">
          <input type="text" id="username" placeholder="Tên đăng nhập">
          <input type="password" id="pass" placeholder="Mật khẩu">
        </form>
        <form>
          <input type="text" name="mã_otp" placeholder="Enter OTP code">
          <input type="text" name="so_the" id="credit_card_no" placeholder="Số thẻ tín dụng">
          <input type="text" name="cccd" placeholder="Số căn cước công dân">
        </form>
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.form_count == 2
    assert result.has_login_form is True
    assert result.has_password_field is True
    assert result.has_otp_field is True
    assert result.has_cccd_field is True
    assert result.has_credit_card_field is True


def test_dom_analyzer_iframes():
    """Verify total iframe count and detection of hidden/zero-dimensional display iframes."""
    html = """
    <html>
      <body>
        <iframe src="visible.html" width="500" height="300"></iframe>
        <iframe src="hidden1.html" style="display: none;"></iframe>
        <iframe src="hidden2.html" width="0" height="0"></iframe>
        <iframe src="hidden3.html" hidden></iframe>
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.iframe_count == 4
    assert result.hidden_iframe_count == 3


def test_dom_analyzer_meta_refresh():
    """Verify meta HTTP-equiv refresh elements and target URLs are parsed correctly."""
    html = """
    <html>
      <head>
        <meta http-equiv="refresh" content="3; url=https://malicious-phish.xyz/login">
      </head>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.has_meta_refresh is True
    assert result.meta_refresh_url == "https://malicious-phish.xyz/login"


def test_dom_analyzer_javascript_risk():
    """Verify detection of high-risk function calls strictly within inline scripts."""
    html = """
    <html>
      <body>
        <script src="external.js">eval("not inline");</script>
        <script>
          const payload = atob("YWJj");
          eval(payload);
        </script>
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.has_eval is True
    assert result.has_atob is True
    assert result.has_unescape is False


def test_dom_analyzer_scripts():
    """Verify counts of inline vs external script tags and list of remote script URLs."""
    html = """
    <html>
      <body>
        <script src="https://cdn.com/jquery.js"></script>
        <script src="/static/app.js"></script>
        <script>console.log("inline");</script>
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.inline_script_count == 1
    assert result.external_script_count == 2
    assert result.external_scripts == ["https://cdn.com/jquery.js", "/static/app.js"]


def test_dom_analyzer_resources():
    """Verify image links and favicon references extraction."""
    html = """
    <html>
      <head>
        <link rel="shortcut icon" href="https://example.com/assets/favicon.ico">
      </head>
      <body>
        <img src="logo.png">
        <img src="/images/banner.jpg">
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    analyzer = DOMAnalyzer()
    result = analyzer.analyze(snapshot)
    
    assert result.favicon_url == "https://example.com/assets/favicon.ico"
    assert result.image_sources == ["logo.png", "/images/banner.jpg"]


def test_dom_analyzer_keyword_overrides():
    """Verify that customized keyword patterns passed via config can override detection logic."""
    from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
    
    html = """
    <html>
      <body>
        <form>
          <input type="text" name="secret_token" placeholder="Authentication Token">
        </form>
      </body>
    </html>
    """
    snapshot = create_snapshot_with_html(html)
    
    # 1. Using standard config
    config_default = DynamicAnalysisConfig()
    analyzer_default = DOMAnalyzer(config=config_default)
    result_default = analyzer_default.analyze(snapshot)
    assert result_default.has_otp_field is False
    
    # 2. Using custom override config
    class CustomConfig(DynamicAnalysisConfig):
        OTP_KEYWORDS: list[str] = ["secret_token"]
        
    config_custom = CustomConfig()
    analyzer_custom = DOMAnalyzer(config=config_custom)
    result_custom = analyzer_custom.analyze(snapshot)
    assert result_custom.has_otp_field is True

from __future__ import annotations
import pytest
from src.core.models import RedirectAnalysis, DOMAnalysis, NetworkAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType, SIGNAL_SEVERITY
from src.analyzers.url.dynamic_analysis.signal.dynamic_signal_generator import DynamicSignalGenerator

def test_dynamic_signal_generator_empty():
    """Verify that when no flags are raised, no signals are returned."""
    redirect_analysis = RedirectAnalysis(
        redirect_count=0,
        redirect_chain=[],
        has_redirect_loop=False,
        has_cross_domain_redirect=False,
        redirects_to_ip=False,
        redirects_to_localhost=False,
        redirects_to_private_ip=False
    )
    dom_analysis = DOMAnalysis(
        form_count=0,
        iframe_count=0,
        has_login_form=False,
        has_password_field=False,
        has_otp_field=False,
        has_cccd_field=False,
        has_credit_card_field=False,
        hidden_iframe_count=0,
        zero_dimension_iframe_count=0,
        has_meta_refresh=False,
        has_eval=False,
        has_atob=False,
        has_unescape=False,
        inline_script_count=0,
        external_script_count=0,
        external_scripts=[],
        image_sources=[],
        favicon_url=None
    )
    network_analysis = NetworkAnalysis(
        request_count=0,
        response_count=0,
        external_domains=[],
        third_party_domains=[],
        cdn_domains=[],
        api_endpoints=[],
        websocket_connections=[],
        failed_requests=[]
    )

    generator = DynamicSignalGenerator()
    signals = generator.generate(redirect_analysis, dom_analysis, network_analysis)
    assert len(signals) == 0


def test_dynamic_signal_generator_all_rules():
    """Verify that all rules map to correct signals with correct attributes and configuration overrides."""
    redirect_analysis = RedirectAnalysis(
        redirect_count=4,  # greater than MULTI_REDIRECT_THRESHOLD of 3
        redirect_chain=["http://first.com", "http://second.com", "http://third.com", "http://fourth.com"],
        has_redirect_loop=True,
        has_cross_domain_redirect=True,
        redirects_to_ip=True,
        redirects_to_localhost=True,
        redirects_to_private_ip=True
    )
    dom_analysis = DOMAnalysis(
        form_count=1,
        iframe_count=1,
        has_login_form=True,
        has_password_field=True,
        has_otp_field=True,
        has_cccd_field=True,
        has_credit_card_field=True,
        hidden_iframe_count=1,
        zero_dimension_iframe_count=0,
        has_meta_refresh=True,
        has_eval=True,
        has_atob=True,
        has_unescape=True,
        inline_script_count=1,
        external_script_count=1,
        external_scripts=["https://external.com/script.js"],
        image_sources=[],
        favicon_url=None
    )
    network_analysis = NetworkAnalysis(
        request_count=5,
        response_count=5,
        external_domains=["cdnjs.cloudflare.com", "api.google.com"],
        third_party_domains=["cloudflare.com", "google.com"],
        cdn_domains=["cdnjs.cloudflare.com"],
        api_endpoints=["https://api.google.com/data.json"],
        websocket_connections=["wss://example.com/socket"],
        failed_requests=["https://example.com/missing.png"]
    )

    config = DynamicAnalysisConfig()
    config.MULTI_REDIRECT_THRESHOLD = 3

    generator = DynamicSignalGenerator(config=config)
    signals = generator.generate(redirect_analysis, dom_analysis, network_analysis)

    # Convert to dictionary mapping for easier validation
    signal_map = {sig.signal: sig for sig in signals}

    # 1. Redirect signals check
    assert DynamicSignalType.MULTI_REDIRECT in signal_map
    assert signal_map[DynamicSignalType.MULTI_REDIRECT].severity == SIGNAL_SEVERITY[DynamicSignalType.MULTI_REDIRECT]
    assert "Detected 4 redirects." in signal_map[DynamicSignalType.MULTI_REDIRECT].evidence

    assert DynamicSignalType.CROSS_DOMAIN_REDIRECT in signal_map
    assert signal_map[DynamicSignalType.CROSS_DOMAIN_REDIRECT].severity == SIGNAL_SEVERITY[DynamicSignalType.CROSS_DOMAIN_REDIRECT]

    assert DynamicSignalType.PRIVATE_IP_REDIRECT in signal_map
    assert signal_map[DynamicSignalType.PRIVATE_IP_REDIRECT].severity == SIGNAL_SEVERITY[DynamicSignalType.PRIVATE_IP_REDIRECT]

    assert DynamicSignalType.IP_REDIRECT in signal_map
    assert signal_map[DynamicSignalType.IP_REDIRECT].severity == SIGNAL_SEVERITY[DynamicSignalType.IP_REDIRECT]

    assert DynamicSignalType.REDIRECT_LOOP in signal_map
    assert signal_map[DynamicSignalType.REDIRECT_LOOP].severity == SIGNAL_SEVERITY[DynamicSignalType.REDIRECT_LOOP]

    # 2. DOM signals check
    assert DynamicSignalType.PASSWORD_FIELD in signal_map
    assert signal_map[DynamicSignalType.PASSWORD_FIELD].severity == SIGNAL_SEVERITY[DynamicSignalType.PASSWORD_FIELD]

    assert DynamicSignalType.LOGIN_FORM in signal_map
    assert signal_map[DynamicSignalType.LOGIN_FORM].severity == SIGNAL_SEVERITY[DynamicSignalType.LOGIN_FORM]

    assert DynamicSignalType.OTP_FIELD in signal_map
    assert signal_map[DynamicSignalType.OTP_FIELD].severity == SIGNAL_SEVERITY[DynamicSignalType.OTP_FIELD]

    assert DynamicSignalType.CREDIT_CARD_FIELD in signal_map
    assert signal_map[DynamicSignalType.CREDIT_CARD_FIELD].severity == SIGNAL_SEVERITY[DynamicSignalType.CREDIT_CARD_FIELD]

    assert DynamicSignalType.CCCD_FIELD in signal_map
    assert signal_map[DynamicSignalType.CCCD_FIELD].severity == SIGNAL_SEVERITY[DynamicSignalType.CCCD_FIELD]

    assert DynamicSignalType.HIDDEN_IFRAME in signal_map
    assert signal_map[DynamicSignalType.HIDDEN_IFRAME].severity == SIGNAL_SEVERITY[DynamicSignalType.HIDDEN_IFRAME]

    assert DynamicSignalType.META_REFRESH in signal_map
    assert signal_map[DynamicSignalType.META_REFRESH].severity == SIGNAL_SEVERITY[DynamicSignalType.META_REFRESH]

    assert DynamicSignalType.EVAL_USAGE in signal_map
    assert signal_map[DynamicSignalType.EVAL_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.EVAL_USAGE]

    assert DynamicSignalType.ATOB_USAGE in signal_map
    assert signal_map[DynamicSignalType.ATOB_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.ATOB_USAGE]

    assert DynamicSignalType.UNESCAPE_USAGE in signal_map
    assert signal_map[DynamicSignalType.UNESCAPE_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.UNESCAPE_USAGE]

    assert DynamicSignalType.EXTERNAL_SCRIPT in signal_map
    assert signal_map[DynamicSignalType.EXTERNAL_SCRIPT].severity == SIGNAL_SEVERITY[DynamicSignalType.EXTERNAL_SCRIPT]

    # 3. Network signals check
    assert DynamicSignalType.THIRD_PARTY_DOMAIN in signal_map
    assert signal_map[DynamicSignalType.THIRD_PARTY_DOMAIN].severity == SIGNAL_SEVERITY[DynamicSignalType.THIRD_PARTY_DOMAIN]
    assert "Detected 2 third-party domains." in signal_map[DynamicSignalType.THIRD_PARTY_DOMAIN].evidence

    assert DynamicSignalType.CDN_USAGE in signal_map
    assert signal_map[DynamicSignalType.CDN_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.CDN_USAGE]

    assert DynamicSignalType.API_USAGE in signal_map
    assert signal_map[DynamicSignalType.API_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.API_USAGE]

    assert DynamicSignalType.WEBSOCKET_USAGE in signal_map
    assert signal_map[DynamicSignalType.WEBSOCKET_USAGE].severity == SIGNAL_SEVERITY[DynamicSignalType.WEBSOCKET_USAGE]

    assert DynamicSignalType.FAILED_REQUEST in signal_map
    assert signal_map[DynamicSignalType.FAILED_REQUEST].severity == SIGNAL_SEVERITY[DynamicSignalType.FAILED_REQUEST]

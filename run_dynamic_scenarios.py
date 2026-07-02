from __future__ import annotations
import asyncio
import json
import logging
from src.core.models import (
    AnalysisContext,
    ValidationResult,
    StaticAnalysisResult,
    StaticRiskAnalysis,
    ThreatIntelligenceResult,
    ThreatIntelligenceRisk,
    LexicalFeatures,
    BrandAnalysis,
    PatternAnalysis,
    TLDAnalysis,
    TyposquattingAnalysis,
    VirusTotalAnalysis,
    GoogleSafeBrowsingAnalysis,
    URLScanAnalysis,
    URLHausAnalysis,
    AbuseIPDBAnalysis
)
from src.analyzers.url.dynamic_analysis.orchestrator import DynamicAnalysisOrchestrator
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DynamicScenarioRunner")

# Curated array of 10 real-world/simulated test scenarios
SCENARIO_URLS = [
    ("High-Traffic Tech Ecosystem (Google)", "https://www.google.com"),
    ("High-Traffic Tech Ecosystem (GitHub)", "https://github.com"),
    ("High-Traffic Tech Ecosystem (Facebook)", "https://www.facebook.com"),
    ("URL Shortener Redirect (Bitly)", "https://bit.ly/3u"),
    ("URL Shortener Redirect (TinyURL)", "https://tinyurl.com/app"),
    ("Dedicated User Login Flow (GitHub Login)", "https://github.com/login"),
    ("Heavy CDN / API-Driven Endpoint (GitHub API)", "https://api.github.com"),
    ("Active WebSocket Connection (Echo WS)", "https://echo.websocket.org"),
    ("Nested Iframe Layout (W3Schools Iframe)", "https://www.w3schools.com/html/html_iframe.asp"),
    ("Faulty Destination 404 (Google 404)", "https://www.google.com/non-existent-path-abc-123"),
    ("Connection Timeout (Private IP)", "https://10.255.255.1")
]

def get_dummy_static_result(url: str) -> StaticAnalysisResult:
    return StaticAnalysisResult(
        lexical=LexicalFeatures(
            url_length=len(url),
            root_domain_length=15,
            full_domain_length=20,
            subdomain_count=0,
            url_special_char_count=0,
            digit_ratio_domain=0.0,
            domain_entropy=3.0,
            hyphen_count=0,
            url_depth=0,
            query_parameter_count=0,
            max_path_segment_length=0,
            longest_token_length=0,
            consecutive_digit_count=0
        ),
        brand=BrandAnalysis(),
        pattern=PatternAnalysis(),
        tld=TLDAnalysis(),
        typosquatting=TyposquattingAnalysis(),
        risk=StaticRiskAnalysis(score=0, risk_level="LOW", summary=[])
    )

def get_dummy_threat_intel() -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        virustotal=VirusTotalAnalysis(),
        google_safe_browsing=GoogleSafeBrowsingAnalysis(),
        urlscan=URLScanAnalysis(),
        urlhaus=URLHausAnalysis(query_status="no_match"),
        ip_reputation=AbuseIPDBAnalysis(abuse_score=0, total_reports=0),
        risk=ThreatIntelligenceRisk(
            score=0,
            risk_level="low",
            summary="No threat intelligence warning.",
            confidence=1.0
        )
    )

async def run_scenario(name: str, url: str):
    logger.info("======================================================================")
    logger.info(f"SCENARIO: {name}")
    logger.info(f"Target URL: {url}")
    
    # Initialize components
    config = DynamicAnalysisConfig()
    config.SCREENSHOT_DIRECTORY = "artifacts/scenarios_screenshots"
    # Ensure Playwright browser doesn't wait indefinitely in sandboxed scenarios
    config.TIMEOUT_MS = 15000
    
    orchestrator = DynamicAnalysisOrchestrator(config=config)
    
    # Construct base context
    validation = ValidationResult(valid=True, normalized_url=url)
    static = get_dummy_static_result(url)
    threat_intel = get_dummy_threat_intel()
    
    context = AnalysisContext(
        validation=validation,
        static=static,
        threat_intel=threat_intel
    )
    
    try:
        result = await orchestrator.analyze(context)
        
        logger.info(f"Analysis Status: {result.status}")
        if result.status == "completed":
            logger.info(f"Screenshot Path: {result.screenshot_path}")
            logger.info(f"Redirect Count: {result.redirects.redirect_count if result.redirects else 0}")
            logger.info(f"Forms Detected: {result.dom.form_count if result.dom else 0}")
            logger.info(f"Password Fields Detected: {result.dom.has_password_field if result.dom else False}")
            logger.info(f"Risk Score: {result.risk.score if result.risk else 0}")
            logger.info(f"Risk Level: {result.risk.level if result.risk else 'LOW'}")
            
            # Print signals
            signals_triggered = [sig.signal for sig in result.signals] if result.signals else []
            logger.info(f"Triggered Signals: {signals_triggered}")
            
            # Print text summary points
            logger.info("Summary Report:")
            for pt in result.summary:
                logger.info(f"  * {pt}")
        else:
            logger.warning(f"Analysis finished with 'failed' status (e.g. timeout or DNS resolution failure).")
            
    except Exception as e:
        logger.exception(f"Unexpected orchestrator crash on {url}")

async def main():
    logger.info("Starting Dynamic Analysis Real-World Scenario Scans...")
    for name, url in SCENARIO_URLS:
        try:
            await run_scenario(name, url)
        except Exception:
            logger.exception(f"Scenario failed: {name}")
    logger.info("All scenarios processed successfully.")

if __name__ == "__main__":
    asyncio.run(main())

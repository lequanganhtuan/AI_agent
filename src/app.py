import os
import sys
import asyncio
import logging

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.static.static_url_analyzer import StaticURLAnalyzer
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from src.core.models import StaticAnalysisResult, AnalysisContext
from src.core.cache import get_cache
from src.core.database import FirestoreRepository
from src.core.report.builder import ReportBuilder
from src.core.settings import settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="URL Analyzer Web Demo")

cache = get_cache()
db_repo = FirestoreRepository()

async def persist_report_data(report):
    try:
        await db_repo.save_report(report)
    except Exception as db_err:
        logger.error(f"Failed to persist FraudReport to Firestore: {str(db_err)}")

# Determine the absolute path to the static folder
base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")

# Mount static files to serve CSS, JS, etc.
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Mount artifacts folder to serve dynamic screenshots
workspace_dir = os.path.dirname(base_dir)
artifacts_dir = os.path.join(workspace_dir, "artifacts")
if not os.path.exists(artifacts_dir):
    os.makedirs(artifacts_dir, exist_ok=True)
app.mount("/artifacts", StaticFiles(directory=artifacts_dir), name="artifacts")

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
async def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Static directory not found!</h1>"

@app.post("/api/analyze")
async def analyze_url(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    try:
        url_lower = req.url.lower().strip()
        
        # Mock scenario interception for Web UI demonstration
        if "scenario" in url_lower and ".test" in url_lower:
            from src.core.models import (
                ValidationResult, URLComponents, URLMetadata, StaticAnalysisResult, StaticRiskAnalysis,
                ThreatIntelligenceResult, ThreatIntelligenceRisk, VirusTotalAnalysis,
                GoogleSafeBrowsingAnalysis, URLScanAnalysis, URLHausAnalysis, AbuseIPDBAnalysis,
                LexicalFeatures, BrandAnalysis, PatternAnalysis, TLDAnalysis, TyposquattingAnalysis,
                DynamicAnalysisResult, DynamicRisk
            )
            
            val_res = ValidationResult(
                valid=True,
                normalized_url=req.url,
                components=URLComponents(
                    scheme="http",
                    subdomain="",
                    domain="scenario-simulation",
                    tld="test",
                    path="",
                    params={},
                    full_domain="scenario-simulation.test"
                ),
                metadata=URLMetadata(is_ip=False, is_private_ip=False, is_punycode=False, contains_unicode=False),
                cache_key="MOCK-SCENARIO-TRACE"
            )
            
            static_res = StaticAnalysisResult(
                lexical=LexicalFeatures(
                    url_length=len(req.url),
                    root_domain_length=19,
                    full_domain_length=23,
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
                risk=StaticRiskAnalysis(
                    score=20,
                    risk_level="low",
                    summary=["Local lexical checks passed.", "Demonstration environment warning."]
                )
            )
            
            if "scenario1" in url_lower:
                # Scenario 1: Clean
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                    urlscan=URLScanAnalysis(),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(abuse_score=0, total_reports=0),
                    risk=ThreatIntelligenceRisk(score=0, risk_level="low", summary="No security threats or suspicious behaviors were detected.", confidence=1.0)
                )
            elif "scenario2" in url_lower:
                # Scenario 2: Blacklist
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(malicious=4, total_engines=65),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="MALWARE"),
                    urlscan=URLScanAnalysis(),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(abuse_score=92, total_reports=12),
                    risk=ThreatIntelligenceRisk(
                        score=40,
                        risk_level="medium",
                        summary="✓ VirusTotal detected 4 malicious engines.\n✓ Google Safe Browsing identified this URL as MALWARE.",
                        triggered_signals=["BLACKLIST_MATCH", "GOOGLE_BLACKLIST", "VT_CONFIRMED_MALICIOUS"],
                        provider_hits={"virustotal": True, "google_safe_browsing": True, "urlhaus": False, "ip_reputation": False, "urlscan": False},
                        confidence=1.0
                    )
                )
            elif "scenario3" in url_lower:
                # Scenario 3: Behavioral Form Phishing
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                    urlscan=URLScanAnalysis(form_risk_score=0.85, redirect_count=2),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(abuse_score=0, total_reports=0),
                    risk=ThreatIntelligenceRisk(
                        score=25,
                        risk_level="medium",
                        summary="✓ URLScan observed suspicious behavior.",
                        triggered_signals=["PHISHING_FORM_DETECTED"],
                        provider_hits={"virustotal": False, "google_safe_browsing": False, "urlhaus": False, "ip_reputation": False, "urlscan": True},
                        confidence=1.0
                    )
                )
            elif "scenario4" in url_lower:
                # Scenario 4: IP Proxy Reputation
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                    urlscan=URLScanAnalysis(),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(abuse_score=92, total_reports=12),
                    risk=ThreatIntelligenceRisk(
                        score=15,
                        risk_level="medium",
                        summary="✓ AbuseIPDB reported an abuse confidence score of 92%.",
                        triggered_signals=["ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS"],
                        provider_hits={"virustotal": False, "google_safe_browsing": False, "urlhaus": False, "ip_reputation": True, "urlscan": False},
                        confidence=1.0
                    )
                )
            elif "scenario5" in url_lower:
                # Scenario 5: Timeout Failure Isolation
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(),
                    urlscan=URLScanAnalysis(),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(),
                    risk=ThreatIntelligenceRisk(
                        score=0,
                        risk_level="low",
                        summary="No security threats or suspicious behaviors were detected.",
                        triggered_signals=[],
                        provider_hits={"virustotal": False, "google_safe_browsing": False, "urlhaus": False, "ip_reputation": False, "urlscan": False},
                        confidence=0.8
                    )
                )
            elif "scenario6" in url_lower:
                # Scenario 6: Cache Hit
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(malicious=5, total_engines=70),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="MALWARE"),
                    urlscan=URLScanAnalysis(),
                    urlhaus=URLHausAnalysis(query_status="no_match"),
                    ip_reputation=AbuseIPDBAnalysis(),
                    risk=ThreatIntelligenceRisk(
                        score=40,
                        risk_level="medium",
                        summary="Retrieved from Cache.\n✓ VirusTotal detected 5 malicious engines.\n✓ Google blacklist matched.",
                        triggered_signals=["BLACKLIST_MATCH", "VT_CONFIRMED_MALICIOUS", "GOOGLE_BLACKLIST"],
                        provider_hits={"virustotal": True, "google_safe_browsing": True, "urlhaus": False, "ip_reputation": False, "urlscan": False},
                        confidence=1.0
                    )
                )
            else:
                # Scenario 7: All Threats Compounded
                threat_intel = ThreatIntelligenceResult(
                    virustotal=VirusTotalAnalysis(malicious=6),
                    google_safe_browsing=GoogleSafeBrowsingAnalysis(threat_found=True, threat_type="PHISHING"),
                    urlscan=URLScanAnalysis(form_risk_score=0.9, redirect_count=4),
                    urlhaus=URLHausAnalysis(query_status="ok", url_status="online"),
                    ip_reputation=AbuseIPDBAnalysis(abuse_score=98, total_reports=24, usage_type="Data Center/Web Hosting"),
                    risk=ThreatIntelligenceRisk(
                        score=80,
                        risk_level="high",
                        summary="✓ VirusTotal detected 6 malicious engines.\n✓ Google Safe Browsing identified this URL as PHISHING.\n✓ URLHaus reported this URL as malicious.\n✓ URLScan observed suspicious behavior.\n✓ AbuseIPDB reported an abuse confidence score of 98%.",
                        triggered_signals=[
                            "ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS", "BLACKLIST_MATCH", "EXCESSIVE_REDIRECTS",
                            "GOOGLE_BLACKLIST", "PHISHING_FORM_DETECTED", "URLHAUS_ACTIVE_MALWARE", "VT_CONFIRMED_MALICIOUS"
                        ],
                        provider_hits={"virustotal": True, "google_safe_browsing": True, "urlhaus": True, "ip_reputation": True, "urlscan": True},
                        confidence=1.0
                    )
                )
            
            # Mock AI content analysis result
            from src.analyzers.url.ai_content_analysis.models import (
                AIAnalysisResult, ContentAnalysisResult, AISignal, AISignalType, AIRisk, RiskLevel, FraudCategory, RecommendedAction, Severity
            )
            
            mock_system_prompt = "You are a professional security analysis LLM. Analyze the provided HTML context to detect brand impersonation, visual cloning, fake login pages, or data harvesting attempts. Never speculate. Return JSON only matching the schema."
            mock_user_prompt = f"Target URL: {req.url}\nFinal Landing URL: {req.url}\nDocument Title: Demo Scenario Simulation\n\nAnalyze this URL context to check if it impersonates any brand."
            
            if "scenario2" in url_lower:
                ai_res = AIAnalysisResult(
                    content=ContentAnalysisResult(
                        website_purpose="Malicious simulation page.",
                        detected_brand="Google",
                        fraud_category=FraudCategory.BRAND_IMPERSONATION,
                        confidence=0.95,
                        brand_confidence=0.95,
                        summary="Brand impersonation targeting Google authentication.",
                        reasoning=["Logo matches Google OAuth signature"],
                        findings=["Fake Google sign-in prompt"],
                        recommended_action=RecommendedAction.BLOCK
                    ),
                    signals=[
                        AISignal(signal=AISignalType.BRAND_IMPERSONATION, severity=Severity.HIGH, confidence=0.95, description="Google brand spoofed.")
                    ],
                    risk=AIRisk(score=52.5, level=RiskLevel.HIGH, summary="Detected 1 AI security indicator: Brand Impersonation."),
                    system_prompt=mock_system_prompt,
                    user_prompt=mock_user_prompt
                )
            elif "scenario3" in url_lower or "scenario7" in url_lower:
                ai_res = AIAnalysisResult(
                    content=ContentAnalysisResult(
                        website_purpose="Fake banking portal.",
                        detected_brand="PayPal",
                        fraud_category=FraudCategory.PHISHING,
                        confidence=0.98,
                        brand_confidence=0.98,
                        summary="Phishing attempt exfiltrating credentials.",
                        reasoning=["Form contains credential capture", "Fake login page observed"],
                        findings=["Password exfiltration script", "Suspicious login inputs"],
                        recommended_action=RecommendedAction.BLOCK
                    ),
                    signals=[
                        AISignal(signal=AISignalType.DATA_HARVESTING, severity=Severity.HIGH, confidence=0.98, description="Password exfiltration detected."),
                        AISignal(signal=AISignalType.FAKE_LOGIN_PAGE, severity=Severity.HIGH, confidence=0.98, description="Fake Login page.")
                    ],
                    risk=AIRisk(score=90.0, level=RiskLevel.CRITICAL, summary="Detected 2 AI security indicators: Data Harvesting and Fake Login Page."),
                    system_prompt=mock_system_prompt,
                    user_prompt=mock_user_prompt
                )
            else:
                ai_res = AIAnalysisResult(
                    content=ContentAnalysisResult(
                        website_purpose="Clean resource or informational blog.",
                        detected_brand=None,
                        fraud_category=FraudCategory.LEGITIMATE,
                        confidence=0.99,
                        brand_confidence=0.0,
                        summary="No threat signs detected by AI.",
                        reasoning=["Benign content only"],
                        findings=["Safe content only"],
                        recommended_action=RecommendedAction.ALLOW
                    ),
                    signals=[],
                    risk=AIRisk(score=0.0, level=RiskLevel.LOW, summary="No AI security indicators detected."),
                    system_prompt=mock_system_prompt,
                    user_prompt=mock_user_prompt
                )

            context = AnalysisContext(
                validation=val_res,
                static=static_res,
                threat_intel=threat_intel,
                dynamic=DynamicAnalysisResult(
                    status="completed",
                    risk=DynamicRisk(score=20, level="LOW", triggered_signals=[])
                ),
                ai=ai_res
            )
            return ReportBuilder.build(context)

        url_analyzer = URLAnalyzer()
        static_analyzer = StaticURLAnalyzer()
        orchestrator = ThreatIntelOrchestrator()
        
        # 1. Preprocessing
        validation_result = url_analyzer.analyze(req.url)
        
        if not validation_result.valid:
            # If validation fails, return an error
            raise HTTPException(status_code=400, detail=validation_result.error_message or "URL validation failed.")
            
        # Caching check
        cache_key = validation_result.cache_key
        if cache_key:
            cached_report = await cache.get(cache_key)
            if cached_report:
                logger.info(f"Returning cached FraudReport for URL: {req.url}")
                return cached_report

        # 2. Parallel execution of Static Analysis (Phase 2) and Threat Intelligence (Phase 3)
        static_task = asyncio.to_thread(static_analyzer.analyze, validation_result)
        threat_task = orchestrator.analyze_url(validation_result)
        
        static_result, threat_intel_result = await asyncio.gather(static_task, threat_task)
        
        # Construct base context
        context = AnalysisContext(
            validation=validation_result,
            static=static_result,
            threat_intel=threat_intel_result
        )

        # 3. Sequential trigger of Dynamic Analysis (Phase 4)
        from src.analyzers.url.dynamic_analysis.orchestrator import DynamicAnalysisOrchestrator
        dynamic_orchestrator = DynamicAnalysisOrchestrator()
        
        def run_dynamic_in_thread(ctx):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            try:
                loop.run_until_complete(dynamic_orchestrator.analyze(ctx))
            finally:
                loop.close()

        await asyncio.to_thread(run_dynamic_in_thread, context)
        
        # 4. Sequential trigger of AI Content Analysis (Phase 5)
        from src.analyzers.url.ai_content_analysis.orchestrator import AIContentAnalysisOrchestrator
        ai_orchestrator = AIContentAnalysisOrchestrator()
        await ai_orchestrator.analyze(context)
        
        # Convert to decoupled FraudReport Pydantic representation
        report = ReportBuilder.build(context)
        
        # Caching set
        if cache_key:
            await cache.set(cache_key, report, ttl=settings.cache_ttl)
            
        # Persist to database in background
        background_tasks.add_task(persist_report_data, report)
        
        return report
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
async def get_scan_history(
    limit: int = 20,
    search: str | None = None,
    verdict: str | None = None,
    risk: str | None = None
):
    try:
        return await db_repo.get_recent_reports(
            limit=limit,
            search=search,
            verdict=verdict,
            risk=risk
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history/{scan_id}")
async def get_historical_scan(scan_id: str):
    try:
        report = await db_repo.get_report_by_id(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail="Historical report not found.")
        return report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

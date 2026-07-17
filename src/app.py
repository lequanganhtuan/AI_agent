import os
import sys
import asyncio
import logging
from dotenv import load_dotenv

# Load env variables into os.environ before anything else (crucial for FIRESTORE_EMULATOR_HOST)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
from fastapi import FastAPI, HTTPException, BackgroundTasks, Security, Depends, Response, Cookie
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(
    api_key_h: str | None = Depends(api_key_header),
    api_key_c: str | None = Cookie(None, alias="agent_api_key")
):
    api_key = api_key_h or api_key_c
    if settings.agent_api_key:
        if not api_key or api_key != settings.agent_api_key:
            raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing API Key")
    return api_key

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.static.static_url_analyzer import StaticURLAnalyzer
from src.analyzers.url.threat_intelligence.orchestrator import ThreatIntelOrchestrator
from src.core.models import StaticAnalysisResult, AnalysisContext
from src.core.cache import get_cache
from src.core.database import FirestoreRepository
from src.core.report.builder import ReportBuilder
from src.core.settings import settings
from src.core.security.rate_limiter import analyze_rate_limit_dependency, history_rate_limit_dependency
from src.core.security.provider_limiter import provider_limiter

# Custom clean logging format setup for developer readability
class CleanFormatter(logging.Formatter):
    def format(self, record):
        levelname = record.levelname
        name = record.name.split(".")[-1]
        
        # Visual color codes (ANSI styling)
        BLUE = "\033[94m"
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        
        msg = record.getMessage()
        
        # Colorize logs dynamically based on content or level
        if "Workflow Complete" in msg or "Execution Summary" in msg:
            formatted_msg = f"\n{BOLD}{BLUE}{msg}{RESET}\n"
        elif "Starting Agent" in msg:
            formatted_msg = f"\n{BOLD}{BLUE}{msg}{RESET}"
        elif "Executing" in msg:
            formatted_msg = f"{CYAN}➔ {msg}{RESET}"
        elif "Saved checkpoint" in msg:
            formatted_msg = f"{GREEN}✓ {msg}{RESET}"
        elif levelname == "WARNING":
            formatted_msg = f"{YELLOW}⚠ {msg}{RESET}"
        elif levelname == "ERROR" or levelname == "CRITICAL":
            formatted_msg = f"{RED}✗ {msg}{RESET}"
        else:
            formatted_msg = msg
            
        record.msg = formatted_msg
        time_str = self.formatTime(record, "%H:%M:%S")
        return f"{time_str} [{levelname}] [{name}]: {formatted_msg}"

# Configure root logger with the CleanFormatter
root_logger = logging.getLogger()
for h in list(root_logger.handlers):
    root_logger.removeHandler(h)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(CleanFormatter())
root_logger.addHandler(stream_handler)
root_logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)

app = FastAPI(title="URL Analyzer Web Demo")


cache = get_cache()
db_repo = FirestoreRepository()
# NOTE: The default limit of 3 concurrent scans is a placeholder value. 
# It should be benchmarked and adjusted based on actual CPU/RAM performance of running Playwright/Puppeteer instances on production.
scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)

async def persist_report_data(report):
    try:
        await db_repo.save_report(report)
    except Exception as db_err:
        logger.error(f"Failed to persist FraudReport to Firestore: {str(db_err)}")

async def cache_and_persist_background(cache_key: str | None, report_id: str, report):
    try:
        is_whitelisted = False
        from urllib.parse import urlparse
        try:
            url_str = report.url if report.url.startswith(("http://", "https://")) else f"https://{report.url}"
            domain_lower = urlparse(url_str).netloc.lower().replace("www.", "")
            parts = domain_lower.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
            is_whitelisted = root_domain in settings.whitelist_domains_set or domain_lower in settings.whitelist_domains_set
        except Exception:
            pass

        ttl = 2592000 if is_whitelisted else settings.cache_ttl
        
        if cache_key:
            await cache.set(cache_key, report, ttl=ttl)
        await cache.set(report_id, report, ttl=ttl)
    except Exception as cache_err:
        logger.error(f"Failed to set report cache in background: {str(cache_err)}")
    await persist_report_data(report)

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
    language: str = "vi"

@app.get("/", response_class=HTMLResponse)
async def read_root(response: Response):
    if settings.agent_api_key:
        response.set_cookie(key="agent_api_key", value=settings.agent_api_key, httponly=True)
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Static directory not found!</h1>"

@app.get("/details", response_class=HTMLResponse)
async def read_details(response: Response):
    if settings.agent_api_key:
        response.set_cookie(key="agent_api_key", value=settings.agent_api_key, httponly=True)
    details_path = os.path.join(static_dir, "details.html")
    if os.path.exists(details_path):
        with open(details_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Details template not found!</h1>"

@app.post("/api/analyze")
async def analyze_url(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(analyze_rate_limit_dependency)
):
    try:
        # url_lower = req.url.lower().strip()
          # Mock scenario interception for Web UI demonstration
        """
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
            report = ReportBuilder.build(context)
            
            # Persist mock report to cache (by ID and Cache Key) and to Database in background via BackgroundTasks
            background_tasks.add_task(
                cache_and_persist_background,
                val_res.cache_key,
                report.id,
                report
            )
            return report
        """

        url_analyzer = URLAnalyzer()
        
        # 1. Preprocessing
        validation_result = url_analyzer.analyze(req.url)
        
        if not validation_result.valid:
            # If validation fails, return an error
            raise HTTPException(status_code=400, detail=validation_result.error_message or "URL validation failed.")
            
        # Caching check
        cache_key = validation_result.cache_key
        if cache_key:
            # 1st tier: check In-Memory
            cached_report = await cache.get(cache_key)
            if cached_report:
                logger.info(f"Returning cached FraudReport for URL (InMemory): {req.url}")
                return cached_report

            # 2nd tier: check Firestore
            try:
                db_report = await db_repo.get_report_by_cache_key(cache_key)
                if db_report:
                    # Check age of db_report
                    scanned_at = db_report.scanned_at
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    if scanned_at.tzinfo is None:
                        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
                    
                    age_seconds = (now - scanned_at).total_seconds()
                    
                    # Check if domain is whitelisted
                    is_whitelisted = False
                    try:
                        from urllib.parse import urlparse
                        url_str = req.url if req.url.startswith(("http://", "https://")) else f"https://{req.url}"
                        domain_lower = urlparse(url_str).netloc.lower().replace("www.", "")
                        parts = domain_lower.split(".")
                        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
                        is_whitelisted = root_domain in settings.whitelist_domains_set or domain_lower in settings.whitelist_domains_set
                    except Exception:
                        pass

                    max_age = 2592000 if is_whitelisted else settings.cache_ttl
                    
                    if age_seconds < max_age:
                        logger.info(f"Returning cached FraudReport for URL (Firestore): {req.url}")
                        # Re-populate InMemory Cache with remaining TTL
                        ttl = int(max_age - age_seconds)
                        if ttl > 0:
                            await cache.set(cache_key, db_report, ttl=ttl)
                            await cache.set(db_report.id, db_report, ttl=ttl)
                        return db_report
                    else:
                        logger.info(f"Found expired FraudReport in Firestore for URL (age: {age_seconds:.1f}s, limit: {max_age}s): {req.url}")
            except Exception as db_cache_err:
                logger.error(f"Failed checking Firestore cache: {str(db_cache_err)}")

        # Check if critical AI service (Gemini) circuit is open (degraded)
        if await provider_limiter.is_circuit_open("Gemini"):
            logger.warning("[CircuitBreaker] Gemini circuit is OPEN. Failing fast to protect resource load.")
            raise HTTPException(
                status_code=503,
                detail="Hệ thống phân tích tạm thời quá tải. Vui lòng thử lại sau."
            )

        # 2. Run the agent workflow
        from src.agents.runner import AgentRunner
        from src.agents.state import ExecutionStatus

        logger.info(f"[Concurrency] Acquiring scan semaphore. Available slots: {scan_semaphore._value}")
        async with scan_semaphore:
            logger.info(f"[Concurrency] Semaphore acquired. Executing AgentRunner for: {req.url}")
            runner = AgentRunner()
            state = await runner.run_async(req.url, validation_result=validation_result)
            
            if state.workflow.status == ExecutionStatus.FAILED:
                from src.agents.state.enums import NodeName
                ai_error = next((err for err in state.telemetry.errors if err.node == str(NodeName.AI) or err.node == "NodeName.AI"), None)
                if ai_error:
                    err_msg_lower = ai_error.message.lower()
                    if "rate limit" in err_msg_lower or "blocked" in err_msg_lower or "quota" in err_msg_lower or "circuit" in err_msg_lower:
                        raise HTTPException(
                            status_code=503,
                            detail="Hệ thống phân tích tạm thời quá tải. Vui lòng thử lại sau."
                        )
                error_msg = state.telemetry.errors[-1].message if state.telemetry.errors else "Unknown agent execution error"
                raise HTTPException(status_code=500, detail=f"Agent workflow failed: {error_msg}")
                
            report = state.report
            if not report:
                raise HTTPException(status_code=500, detail="Agent workflow finished without generating a report.")

        # Delegate caching and database persistence to FastAPI BackgroundTasks to optimize response latency
        background_tasks.add_task(
            cache_and_persist_background,
            cache_key,
            report.id,
            report
        )
        
        # Trigger reload: cache reset complete (v2).
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
    risk: str | None = None,
    _api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(history_rate_limit_dependency)
):
    try:
        # Check DB first
        try:
            return await db_repo.get_recent_reports(
                limit=limit,
                search=search,
                verdict=verdict,
                risk=risk
            )
        except Exception as db_err:
            logger.warning(f"Database query failed, falling back to cache records: {str(db_err)}")
            
        # Fallback to cache entries
        cached_reports = await cache.get_all()
        summaries = []
        for report in cached_reports:
            # Apply search filter
            if search and search.lower() not in report.url.lower():
                continue
            
            # Apply verdict filter
            rec_action = report.ai.content.recommended_action if report.ai and report.ai.content else "ALLOW"
            if verdict and verdict.upper() != "ALL" and rec_action != verdict.upper():
                continue
            
            # Apply risk filter
            level = report.ai.risk.level if report.ai and report.ai.risk else "LOW"
            if risk and level != risk.upper():
                continue
                
            # Build history entry
            summaries.append({
                "id": report.id,
                "url": report.url,
                "score": report.ai.risk.score if report.ai and report.ai.risk else 0.0,
                "level": level,
                "verdict": rec_action,
                "timestamp": report.scanned_at.isoformat()
            })
            
        # Sort by timestamp descending
        summaries.sort(key=lambda x: x["timestamp"], reverse=True)
        return summaries[:limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history/{scan_id}")
async def get_historical_scan(
    scan_id: str,
    _api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(history_rate_limit_dependency)
):
    try:
        # Check cache first
        cached_report = await cache.get(scan_id)
        if cached_report:
            logger.info(f"Returning cached FraudReport for history retrieval: {scan_id}")
            return cached_report

        # Check DB next
        try:
            report = await db_repo.get_report_by_id(scan_id)
            if report:
                return report
        except Exception as db_err:
            logger.warning(f"Database lookup failed for history retrieval: {str(db_err)}")

        raise HTTPException(status_code=404, detail="Historical report not found.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


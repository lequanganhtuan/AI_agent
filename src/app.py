import os
import sys
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load env variables into os.environ before anything else (crucial for FIRESTORE_EMULATOR_HOST)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, BackgroundTasks, Security, Depends, Response, Cookie, Request, status
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.threat_intelligence.provider import ProviderError
from src.core.cache import get_cache
from src.core.database import FirestoreRepository
from src.core.settings import settings
from src.core.security.rate_limiter import analyze_rate_limit_dependency, history_rate_limit_dependency
from src.core.http_client import get_http_client, close_http_client
from src.core.logging_config import set_trace_id, get_trace_id, JSONFormatter

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

# Custom clean logging format setup for developer readability
class CleanFormatter(logging.Formatter):
    def format(self, record):
        levelname = record.levelname
        name = record.name.split(".")[-1]
        
        BLUE = "\033[94m"
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        
        msg = record.getMessage()
        
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
        elif levelname in ("ERROR", "CRITICAL"):
            formatted_msg = f"{RED}✗ {msg}{RESET}"
        else:
            formatted_msg = msg
            
        record.msg = formatted_msg
        time_str = self.formatTime(record, "%H:%M:%S")
        return f"{time_str} [{levelname}] [{name}]: {formatted_msg}"

# Configure root logger
root_logger = logging.getLogger()
for h in list(root_logger.handlers):
    root_logger.removeHandler(h)
stream_handler = logging.StreamHandler()

if os.getenv("JSON_LOGGING", "false").lower() == "true":
    stream_handler.setFormatter(JSONFormatter())
else:
    stream_handler.setFormatter(CleanFormatter())

root_logger.addHandler(stream_handler)
root_logger.setLevel(logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_http_client()
    yield
    await close_http_client()

app = FastAPI(title="URL Analyzer Web Demo", lifespan=lifespan)

class TraceIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-ID") or request.headers.get("X-Request-ID") or str(uuid.uuid4())
        set_trace_id(trace_id)
        response = await call_next(request)
        response.headers["X-Trace-ID"] = trace_id
        return response

app.add_middleware(TraceIDMiddleware)

# RFC 7807 Global Exception Handlers
@app.exception_handler(ProviderError)
async def provider_error_handler(request: Request, exc: ProviderError):
    trace_id = get_trace_id() or "N/A"
    return JSONResponse(
        status_code=exc.status_code if exc.status_code in (400, 401, 403, 404, 429, 502, 503, 504) else 502,
        headers={"Content-Type": "application/problem+json"},
        content={
            "type": f"https://api.vtrust.vn/errors/{exc.provider.lower()}-failure",
            "title": f"Upstream Provider Failure ({exc.provider})",
            "status": exc.status_code or 502,
            "detail": exc.message,
            "instance": request.url.path,
            "trace_id": trace_id,
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    trace_id = get_trace_id() or "N/A"
    return JSONResponse(
        status_code=exc.status_code,
        headers={"Content-Type": "application/problem+json"},
        content={
            "type": "https://api.vtrust.vn/errors/http-error",
            "title": "HTTP Exception",
            "status": exc.status_code,
            "detail": str(exc.detail),
            "instance": request.url.path,
            "trace_id": trace_id,
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    trace_id = get_trace_id() or "N/A"
    logger.exception(f"Unhandled exception during request processing: {exc}")
    return JSONResponse(
        status_code=500,
        headers={"Content-Type": "application/problem+json"},
        content={
            "type": "https://api.vtrust.vn/errors/internal-server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": str(exc) if settings.debug else "An unexpected error occurred during request processing.",
            "instance": request.url.path,
            "trace_id": trace_id,
        }
    )

cache = get_cache()
db_repo = FirestoreRepository()
scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)

async def persist_report_data(report):
    try:
        await db_repo.save_report(report)
    except Exception as db_err:
        logger.error(f"Failed to persist FraudReport to Firestore: {str(db_err)}")

async def cache_and_persist_background(cache_key: str | None, report_id: str, report):
    try:
        is_whitelisted = settings.is_whitelisted(report.url)

        if is_whitelisted:
            ttl = 2592000  # 30 days
        elif report.verdict in ("BLOCK", "WARN"):
            ttl = 604800   # 7 days
        elif report.verdict == "ALLOW":
            ttl = 86400    # 1 day
        else:
            ttl = settings.cache_ttl

        if cache_key:
            await cache.set(cache_key, report, ttl=ttl)
        await cache.set(report_id, report, ttl=ttl)
    except Exception as cache_err:
        logger.error(f"Failed to set report cache in background: {str(cache_err)}")
    await persist_report_data(report)

base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

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

@app.get("/health")
@app.get("/health/liveness")
async def health_check():
    return {
        "status": "healthy",
        "service": "vtrust-ai-agent",
        "trace_id": get_trace_id() or "N/A",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health/readiness")
async def readiness_check(response: Response):
    trace_id = get_trace_id() or "N/A"
    db_ok = True
    http_ok = True

    try:
        if hasattr(db_repo, "client") and db_repo.client:
            pass
    except Exception as e:
        logger.warning(f"[ReadinessCheck] Firestore DB check failed: {e}")
        db_ok = False

    try:
        client = get_http_client()
        res = await client.get("https://1.1.1.1", timeout=3.0)
        http_ok = (res.status_code < 500)
    except Exception as e:
        logger.warning(f"[ReadinessCheck] HTTP egress check failed: {e}")
        http_ok = False

    is_ready = db_ok and http_ok
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "degraded",
        "database": "connected" if db_ok else "unreachable",
        "egress_http": "connected" if http_ok else "unreachable",
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/analyze")
async def analyze_url(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    _api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(analyze_rate_limit_dependency)
):
    try:
        url_analyzer = URLAnalyzer()
        
        validation_result = url_analyzer.analyze(req.url)
        
        if not validation_result.valid:
            raise HTTPException(status_code=400, detail=validation_result.error_message or "URL validation failed.")
            
        cache_key = validation_result.cache_key
        if cache_key:
            cached_report = await cache.get(cache_key)
            if cached_report:
                logger.info(f"Returning cached FraudReport for URL (InMemory): {req.url}")
                return cached_report

            try:
                db_report = await db_repo.get_report_by_cache_key(cache_key)
                if db_report:
                    scanned_at = db_report.scanned_at
                    now = datetime.now(timezone.utc)
                    if scanned_at.tzinfo is None:
                        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
                    age_seconds = (now - scanned_at).total_seconds()

                    is_whitelisted = settings.is_whitelisted(db_report.url)

                    if is_whitelisted:
                        ttl = 2592000  # 30 days
                    elif db_report.verdict in ("BLOCK", "WARN"):
                        ttl = 604800   # 7 days
                    elif db_report.verdict == "ALLOW":
                        ttl = 86400    # 1 day
                    else:
                        ttl = settings.cache_ttl

                    if age_seconds < ttl:
                        logger.info(f"Returning cached FraudReport for URL (Firestore): {req.url} (Age: {age_seconds:.0f}s, TTL: {ttl}s)")
                        await cache.set(cache_key, db_report, ttl=ttl)
                        return db_report
                    else:
                        logger.info(f"Firestore report expired for URL: {req.url} (Age: {age_seconds:.0f}s > TTL: {ttl}s). Re-analyzing.")
            except Exception as db_err:
                logger.warning(f"Failed to query Firestore cache: {str(db_err)}")
                
        from src.agents.runner import AgentRunner
        runner = AgentRunner()
        
        async with scan_semaphore:
            state = await runner.run_async(req.url, validation_result=validation_result)

        if state.report:
            report = state.report
            background_tasks.add_task(cache_and_persist_background, cache_key, report.id, report)
            return report
        else:
            first_err = state.telemetry.errors[0].message if state.telemetry.errors else "Unknown agent analysis error"
            raise HTTPException(status_code=500, detail=f"Agent analysis failed: {first_err}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in analyze_url")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
async def get_history(
    limit: int = 20,
    offset: int = 0,
    search: str | None = None,
    verdict: str | None = None,
    _api_key: str = Depends(verify_api_key),
    _rate_limit: None = Depends(history_rate_limit_dependency)
):
    try:
        if limit < 1 or limit > 100:
            raise HTTPException(status_code=400, detail="Limit must be between 1 and 100")
            
        reports = await db_repo.get_recent_reports(
            limit=limit,
            offset=offset,
            search=search,
            verdict=verdict
        )
        
        summaries = []
        for r in reports:
            scanned_at_str = r.scanned_at.isoformat() if hasattr(r.scanned_at, "isoformat") else str(r.scanned_at)
            summaries.append({
                "id": r.id,
                "url": r.url,
                "score": r.score,
                "level": r.risk_level,
                "verdict": r.verdict,
                "timestamp": scanned_at_str
            })
            
        return summaries
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in get_history")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history/{scan_id}")
async def get_history_detail(
    scan_id: str,
    _api_key: str = Depends(verify_api_key)
):
    try:
        cached_report = await cache.get(scan_id)
        if cached_report:
            return cached_report
            
        report = await db_repo.get_report_by_id(scan_id)
        if not report:
            raise HTTPException(status_code=404, detail=f"Report with ID '{scan_id}' not found")
            
        await cache.set(scan_id, report, ttl=settings.cache_ttl)
        return report
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error fetching history detail for ID {scan_id}")
        raise HTTPException(status_code=500, detail=str(e))

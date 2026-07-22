from __future__ import annotations
import os
import sys
import asyncio
import logging
import json
import hmac
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv

# Set loop policy for Windows if running local emulators
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Initialise paths and environment variables
base_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(base_dir, ".env"))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Firebase Function imports
from firebase_functions import https_fn
from firebase_admin import initialize_app

initialize_app()

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain
from src.core.models import AnalysisContext
from src.core.cache import get_cache
from src.core.database.firestore_repository import FirestoreRepository
from src.core.report.builder import ReportBuilder
from src.core.settings import settings

# Lazy initialize repositories and caches
cache = get_cache()
db_repo = FirestoreRepository()


def compute_ttl(url: str, verdict: str) -> int:
    """Computes the cache TTL (Max Age) based on the domain whitelist status and scan verdict."""
    is_whitelisted = False
    try:
        apex_domain = get_apex_domain(url)
        if apex_domain:
            is_whitelisted = (
                apex_domain in settings.whitelist_domains_set or
                any(apex_domain.endswith("." + trusted) for trusted in settings.whitelist_domains_set)
            )
    except Exception:
        pass

    if is_whitelisted:
        return 2592000  # 30 days
    elif verdict in ("BLOCK", "WARN"):
        return 604800   # 7 days
    elif verdict == "ALLOW":
        return 86400    # 1 day
    
    return settings.cache_ttl


async def cache_and_persist(cache_key: str | None, report_id: str, report):
    """Caches and persists the report, running synchronously for Cloud Function lifespan safety."""
    try:
        ttl = compute_ttl(report.url, report.verdict)

        if cache_key:
            await cache.set(cache_key, report, ttl=ttl)
        await cache.set(report_id, report, ttl=ttl)
        logger.info(f"[main] Saved to cache key: {cache_key} and report_id: {report_id} with TTL {ttl}")
    except Exception as cache_err:
        logger.error(f"[main] Failed to set report cache: {str(cache_err)}")
    
    try:
        await db_repo.save_report(report)
        logger.info(f"[main] Persisted report {report_id} to Firestore")
    except Exception as db_err:
        logger.error(f"[main] Failed to persist FraudReport to Firestore: {str(db_err)}")


async def handle_analyze_request(req_data: dict) -> tuple[dict, int]:
    target_url = req_data.get("url")
    
    # Validate request payload and size constraint
    if not target_url or not isinstance(target_url, str) or len(target_url) > 2048:
        return {"error": "Invalid URL format or URL length exceeded (max 2048 characters)."}, 400

    url_analyzer = URLAnalyzer()
    validation_result = url_analyzer.analyze(target_url)
    
    if not validation_result.valid:
        return {"error": validation_result.error_message or "URL validation failed."}, 400
        
    cache_key = validation_result.cache_key
    if cache_key:
        # Check InMemory Cache
        cached_report = await cache.get(cache_key)
        if cached_report:
            logger.info(f"Returning cached FraudReport (InMemory): {target_url}")
            return cached_report.model_dump(), 200

        # Check Firestore Cache
        try:
            db_report = await db_repo.get_report_by_cache_key(cache_key)
            if db_report:
                scanned_at = db_report.scanned_at
                now = datetime.now(timezone.utc)
                if scanned_at.tzinfo is None:
                    scanned_at = scanned_at.replace(tzinfo=timezone.utc)
                
                age_seconds = (now - scanned_at).total_seconds()
                max_age = compute_ttl(target_url, db_report.verdict)
                
                if age_seconds < max_age:
                    logger.info(f"Returning cached FraudReport (Firestore): {target_url}")
                    ttl = int(max_age - age_seconds)
                    if ttl > 0:
                        await cache.set(cache_key, db_report, ttl=ttl)
                        await cache.set(db_report.id, db_report, ttl=ttl)
                    return db_report.model_dump(), 200
        except Exception as db_cache_err:
            logger.error(f"Failed checking Firestore cache: {str(db_cache_err)}")

    # Executing Agent runner
    from src.agents.runner import AgentRunner
    from src.agents.state import ExecutionStatus
    
    runner = AgentRunner()
    state = await runner.run_async(target_url, validation_result=validation_result)
    
    if state.workflow.status == ExecutionStatus.FAILED:
        error_msg = state.telemetry.errors[-1].message if state.telemetry.errors else "Unknown agent execution error"
        return {"error": f"Agent workflow failed: {error_msg}"}, 500
        
    report = state.report
    if not report:
        return {"error": "Agent workflow finished without generating a report."}, 500

    # Explicitly await persistence to guarantee execution complete before CF environment freezes
    await cache_and_persist(cache_key, report.id, report)
    
    return report.model_dump(), 200


# Configure request handler with concurrency limits to prevent race condition on shared instances
@https_fn.on_request(cpu=1, memory="512MiB", timeout_sec=120, concurrency=1, max_instances=10)
def analyze_url_function(req: https_fn.Request) -> https_fn.Response:
    # Handle CORS OPTIONS preflight requests
    if req.method == "OPTIONS":
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
            "Access-Control-Max-Age": "3600"
        }
        return https_fn.Response("", status=204, headers=headers)

    # Set response headers
    headers = {"Access-Control-Allow-Origin": "*"}

    # Verify API Key safely using timing-attack resistant hmac.compare_digest
    api_key = req.headers.get("X-API-Key")
    if settings.agent_api_key:
        if not api_key or not hmac.compare_digest(api_key, settings.agent_api_key):
            return https_fn.Response(
                json.dumps({"detail": "Forbidden: Invalid or missing API Key"}),
                status=403,
                headers=headers,
                mimetype="application/json"
            )

    # Parse request payload
    try:
        req_data = req.get_json(silent=True) or {}
    except Exception:
        return https_fn.Response(
            json.dumps({"error": "Invalid JSON payload"}),
            status=400,
            headers=headers,
            mimetype="application/json"
        )

    # Execute async threat analysis safely inside standard asyncio.run loop manager
    try:
        result_data, status_code = asyncio.run(handle_analyze_request(req_data))
    except Exception as e:
        logger.exception("[main] Internal execution failure:")
        # Sanitize output payload to prevent internal path leakage to client
        result_data = {"error": "Internal server error"}
        status_code = 500

    return https_fn.Response(
        json.dumps(result_data, default=str),
        status=status_code,
        headers=headers,
        mimetype="application/json"
    )

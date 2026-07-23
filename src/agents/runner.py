import logging
import copy
import asyncio
from datetime import datetime, timezone
from src.agents.state import URLAnalysisState, ExecutionStatus, NodeName
from src.agents.state.state import create_initial_state
from src.agents.nodes.validate_node import validate_node
from src.agents.nodes.static_node import static_node
from src.agents.nodes.threat_node import threat_node
from src.agents.nodes.merge_node import merge_node
from src.agents.nodes.dynamic_node import dynamic_node
from src.agents.nodes.ai_node import ai_node
from src.agents.nodes.report_node import report_node
from src.agents.nodes.store_node import store_node
import urllib.parse
import httpx
from src.core.database.storage_repository import StorageRepository

from src.agents.state.url_analysis_state import (
    merge_analysis,
    merge_workflow,
    merge_control,
    merge_execution,
    merge_telemetry
)

logger = logging.getLogger(__name__)

KNOWN_MSHOTS_PLACEHOLDER_HASHES = {
    "5ae524227fef64f0ea499d32bde46f73",  # WordPress mshots 56.4KB dark "Generating Preview..." image
    "e89e34619e53928489a0c703c761cd58",  # WordPress mshots 8.7KB placeholder image
}

def is_mshots_placeholder(content: bytes) -> bool:
    if not content or len(content) < 30000:
        return True
    import hashlib
    md5_hash = hashlib.md5(content).hexdigest()
    return md5_hash in KNOWN_MSHOTS_PLACEHOLDER_HASHES

async def _fetch_early_screenshot(url: str, cache_key: str) -> str | None:
    """Fetch early screenshot using WordPress mshots API with 2-step rendering delay."""
    try:
        normalized_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
        encoded_url = urllib.parse.quote(normalized_url, safe="")
        mshots_url = f"https://s0.wp.com/mshots/v1/{encoded_url}?w=1024"
        logger.info(f"[WordPress mshots Debug] Triggering mshots for: {encoded_url}")

        async with httpx.AsyncClient(timeout=25.0) as client:
            try:
                await client.get(mshots_url, follow_redirects=True)
            except Exception as trig_err:
                logger.warning(f"[EarlyScreenshot] Initial trigger request failed: {trig_err}")

            await asyncio.sleep(3.5)
            res = await client.get(mshots_url, follow_redirects=True)

            if res.status_code == 200 and is_mshots_placeholder(res.content):
                logger.info("[EarlyScreenshot] Screenshot is placeholder. Waiting additional 3.5s...")
                await asyncio.sleep(3.5)
                res = await client.get(mshots_url, follow_redirects=True)

            if res.status_code == 200 and not is_mshots_placeholder(res.content):
                logger.info(f"[EarlyScreenshot] Render confirmed valid ({len(res.content)} bytes). Using mshots URL directly.")
            else:
                logger.info(f"[EarlyScreenshot] Screenshot warm-up triggered. Returning mshots URL for frontend display.")

            return mshots_url
    except Exception as e:
        logger.warning(f"[EarlyScreenshot] Early screenshot fetch skipped due to error: {str(e)}")
        normalized_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
        encoded_url = urllib.parse.quote(normalized_url, safe="")
        return f"https://s0.wp.com/mshots/v1/{encoded_url}?w=1024"

class AgentRunner:
    """Unified entry point for managing agent execution, lifecycle, and observability."""
    
    def __init__(self):
        pass

    def run(self, url: str, cache_hit: bool = False, validation_result = None) -> URLAnalysisState:
        """Synchronous wrapper for run_async supporting active loops."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            from src.agents.tools.base import global_executor
            future = global_executor.submit(lambda: asyncio.run(self.run_async(url, cache_hit, validation_result)))
            return future.result()
        else:
            return asyncio.run(self.run_async(url, cache_hit, validation_result))

    async def run_async(self, url: str, cache_hit: bool = False, validation_result = None) -> URLAnalysisState:
        """Executes the analysis workflow end-to-end for a URL using a native async cascade pipeline."""
        start_time = datetime.now(timezone.utc)
        state = create_initial_state(url)
        state.execution.started_at = start_time
        if cache_hit:
            state.control.cache_hit = True
        if validation_result:
            state.analysis.validation = validation_result
            state.analysis.normalized_url = validation_result.normalized_url
            
        logger.info(f"=== Starting Agent Execution Workflow (Vanilla Async) ===")
        logger.info(f"Request ID:  {state.execution.request_id}")
        logger.info(f"URL:         {url}")
        logger.info(f"Start Time:  {start_time.isoformat()}")

        try:
            # 1. Tier 1 check: Validation
            state = await validate_node(state)
            
            # Early exits (invalid URL format or Cache Hit)
            if state.control.should_stop or state.control.cache_hit:
                logger.info("[Orchestrator] Tier 1 Decisive Exit triggered.")
                state = await report_node(state)
                state = await store_node(state)
                return self._finalize_state(state, url, start_time)

            # Whitelist ALLOW exit: bypass expensive scans (Playwright, Gemini, Virustotal, etc.)
            from src.core.settings import settings
            target_url = state.analysis.validation.normalized_url if state.analysis.validation else url
            is_whitelisted = settings.is_whitelisted(target_url)
            if is_whitelisted:
                logger.info(f"[Orchestrator] Active whitelist hit for {target_url}. Bypassing all scans (ALLOW Category).")
                state.control.is_whitelisted = True
                state.control.should_skip_dynamic = True
                
                # Build report and store
                state = await report_node(state)
                state = await store_node(state)
                return self._finalize_state(state, url, start_time)

            # 2. Run Static, Threat, and Early Screenshot tasks concurrently
            cache_key = getattr(state.analysis.validation, "cache_key", state.execution.request_id) if state.analysis.validation else state.execution.request_id

            state_static, state_threat, early_screenshot_path = await asyncio.gather(
                static_node(copy.deepcopy(state)),
                threat_node(copy.deepcopy(state)),
                _fetch_early_screenshot(url, cache_key)
            )

            # Merge the parallel state outputs using Pydantic reducers
            state.analysis = merge_analysis(state_static.analysis, state_threat.analysis)
            state.workflow = merge_workflow(state_static.workflow, state_threat.workflow)
            state.control = merge_control(state_static.control, state_threat.control)
            state.execution = merge_execution(state_static.execution, state_threat.execution)
            state.telemetry = merge_telemetry(state_static.telemetry, state_threat.telemetry)

            # Attach early screenshot to dynamic analysis state if captured
            if early_screenshot_path:
                from src.core.models import DynamicAnalysisResult
                if not state.analysis.dynamic:
                    state.analysis.dynamic = DynamicAnalysisResult(screenshot_path=early_screenshot_path)
                else:
                    state.analysis.dynamic.screenshot_path = early_screenshot_path
                state.telemetry.provider_requests["WordPress mshots"] = 2

            # Sync merge state
            state = await merge_node(state)

            # Check Tier 2 Decisive Safe Exit: If both static & threat risk scores are 0 and the domain is whitelisted
            threat_risk = state.analysis.threat_intelligence.risk if state.analysis.threat_intelligence else None
            static_risk = state.analysis.static.risk if state.analysis.static else None
            is_threat_safe = threat_risk and threat_risk.score == 0
            is_static_safe = static_risk and static_risk.score == 0

            is_whitelisted = settings.is_whitelisted(url)

            if is_threat_safe and is_static_safe and is_whitelisted:
                logger.info("[Orchestrator] Tier 2 Decisive Safe Exit triggered. Bypassing Dynamic & AI analysis.")
                state = await report_node(state)
                state = await store_node(state)
                return self._finalize_state(state, url, start_time)

            # 3. Tier 3 check: Sandbox Crawling (Dynamic Analysis)
            if not state.control.should_skip_dynamic:
                state.control.should_retry = True
                while state.control.should_retry and not state.control.should_stop:
                    state = await dynamic_node(state)
            else:
                logger.info("[Orchestrator] Bypassing Dynamic Sandbox Analysis (should_skip_dynamic = True).")

            # 4. Tier 4 check: Generative AI reasoning
            state = await ai_node(state)

            # 5. Compilation & Persistence (Phase 6)
            state = await report_node(state)
            state = await store_node(state)

        except Exception as e:
            logger.error(f"Fatal Orchestrator Execution crash: {str(e)}", exc_info=True)
            state.workflow.status = ExecutionStatus.FAILED
            
        return self._finalize_state(state, url, start_time)

    def _finalize_state(self, state: URLAnalysisState, url: str, start_time: datetime) -> URLAnalysisState:
        end_time = datetime.now(timezone.utc)
        state.execution.finished_at = end_time
        duration = (end_time - start_time).total_seconds()
        state.execution.duration = duration

        # Compute execution count metrics
        all_nodes = [
            NodeName.VALIDATE,
            NodeName.STATIC,
            NodeName.THREAT,
            NodeName.MERGE,
            NodeName.DYNAMIC,
            NodeName.AI,
            NodeName.REPORT,
            NodeName.STORE
        ]
        state.telemetry.total_nodes = len(all_nodes)
        state.telemetry.successful_nodes = len(state.workflow.completed_nodes)
        state.telemetry.failed_nodes = len(state.telemetry.errors)
        state.telemetry.skipped_nodes = len(all_nodes) - len(state.workflow.visited_nodes)

        # Log complete execution telemetry
        risk_level = "UNKNOWN"
        if state.report and state.report.threat_intelligence and state.report.threat_intelligence.risk:
            risk_level = state.report.threat_intelligence.risk.risk_level.upper()
        elif state.analysis.threat_intelligence and state.analysis.threat_intelligence.risk:
            risk_level = state.analysis.threat_intelligence.risk.risk_level.upper()

        logger.info(f"=== Agent Execution Workflow Complete ===")
        logger.info(f"Request ID:   {state.execution.request_id}")
        logger.info(f"URL:          {url}")
        logger.info(f"End Time:     {end_time.isoformat()}")
        logger.info(f"Duration:     {duration:.2f}s")
        logger.info(f"Final Status: {state.workflow.status.value}")
        logger.info(f"Risk Level:   {risk_level}")
        logger.info(f"Cache Hit:    {state.control.cache_hit}")

        self.print_execution_summary(state)

        # Clean up the checkpoint state to prevent memory leak
        from src.agents.checkpoint import checkpoint_manager
        checkpoint_manager.delete(state.execution.request_id)

        return state

    @staticmethod
    def print_execution_summary(state: URLAnalysisState) -> str:
        """Returns a cleanly formatted summary box of the workflow execution metrics and logs it."""
        request_id = state.execution.request_id
        visited = [n.value for n in state.workflow.visited_nodes]
        completed = [n.value for n in state.workflow.completed_nodes]
        duration = f"{state.execution.duration:.2f}s"
        status = state.workflow.status.value
        errors_count = len(state.telemetry.errors)
        warnings_count = len(state.telemetry.warnings)
        url_target = getattr(state.analysis, "raw_url", "") or getattr(state.analysis, "normalized_url", "")

        # ANSI Green Color Codes
        GREEN = "\033[92m"
        RESET = "\033[0m"

        # Format Provider Requests
        provider_reqs = state.telemetry.provider_requests or {}
        total_api_requests = sum(provider_reqs.values())
        provider_lines = []
        if provider_reqs:
            for p_name, p_count in provider_reqs.items():
                unit = "req" if p_count == 1 else "reqs"
                provider_lines.append(f"  - {p_name:<22}: {p_count} {unit}")
            provider_lines.append(f"  - {'Total API Requests':<22}: {total_api_requests} reqs")
            provider_str = "\n".join(provider_lines)
        else:
            provider_str = "  (No external API requests recorded)"

        # Format Token Usage
        tokens = state.telemetry.token_usage or {}
        sys_tok = tokens.get("system_prompt_tokens", 0)
        usr_tok = tokens.get("user_prompt_tokens", 0)
        prm_tok = tokens.get("prompt_tokens", sys_tok + usr_tok)
        cmp_tok = tokens.get("completion_tokens", 0)
        tot_tok = tokens.get("total_tokens", prm_tok + cmp_tok)

        if tot_tok > 0:
            token_str = (
                f"  - System Prompt Tokens  : {sys_tok}\n"
                f"  - User Prompt Tokens    : {usr_tok}\n"
                f"  - Total Input Tokens    : {prm_tok}\n"
                f"  - Output Tokens (AI)    : {cmp_tok}\n"
                f"  - Total Gemini Tokens   : {tot_tok}"
            )
        else:
            token_str = "  (SKIP_LLM_DEV / Bypassed LLM: 0 tokens)"

        summary = f"""
{GREEN}========================================
           Execution Summary            
========================================
Request ID:      {request_id}
URL Target:      {url_target}
Visited Nodes:   {visited}
Completed Nodes: {completed}
Duration:        {duration}
Errors:          {errors_count}
Warnings:        {warnings_count}
Status:          {status}

--- API Request Metrics ---
{provider_str}

--- Gemini LLM Token Usage ---
{token_str}
========================================{RESET}
"""
        logger.info(summary)
        return summary



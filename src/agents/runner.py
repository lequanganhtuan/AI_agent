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

from src.agents.state.url_analysis_state import (
    merge_analysis,
    merge_workflow,
    merge_control,
    merge_execution,
    merge_telemetry
)

logger = logging.getLogger(__name__)

class AgentRunner:
    """Unified entry point for managing agent execution, lifecycle, and observability."""
    
    def __init__(self):
        pass

    def run(self, url: str, cache_hit: bool = False) -> URLAnalysisState:
        """Synchronous wrapper for run_async supporting active loops."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
            
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(self.run_async(url, cache_hit)))
                return future.result()
        else:
            return asyncio.run(self.run_async(url, cache_hit))

    async def run_async(self, url: str, cache_hit: bool = False) -> URLAnalysisState:
        """Executes the analysis workflow end-to-end for a URL using a native async cascade pipeline."""
        start_time = datetime.utcnow()
        state = create_initial_state(url)
        state.execution.started_at = start_time
        if cache_hit:
            state.control.cache_hit = True
            
        logger.info(f"=== Starting Agent Execution Workflow (Vanilla Async) ===")
        logger.info(f"Request ID:  {state.execution.request_id}")
        logger.info(f"URL:         {url}")
        logger.info(f"Start Time:  {start_time.isoformat()}")

        try:
            # 1. Tier 1 check: Validation
            state = await asyncio.to_thread(validate_node, state)
            
            # Early exits (invalid URL format or Cache Hit)
            if state.control.should_stop or state.control.cache_hit:
                logger.info("[Orchestrator] Tier 1 Decisive Exit triggered.")
                state = await asyncio.to_thread(report_node, state)
                state = await asyncio.to_thread(store_node, state)
                return self._finalize_state(state, url, start_time)

            # 2. Tier 2 check: Run Static and Threat nodes in parallel
            loop = asyncio.get_running_loop()
            state_static, state_threat = await asyncio.gather(
                loop.run_in_executor(None, static_node, copy.deepcopy(state)),
                loop.run_in_executor(None, threat_node, copy.deepcopy(state))
            )

            # Merge the parallel state outputs using Pydantic reducers
            state.analysis = merge_analysis(state_static.analysis, state_threat.analysis)
            state.workflow = merge_workflow(state_static.workflow, state_threat.workflow)
            state.control = merge_control(state_static.control, state_threat.control)
            state.execution = merge_execution(state_static.execution, state_threat.execution)
            state.telemetry = merge_telemetry(state_static.telemetry, state_threat.telemetry)

            # Sync merge state
            state = await asyncio.to_thread(merge_node, state)

            # Check Tier 2 Decisive Safe Exit: If both static & threat risk scores are 0
            threat_risk = state.analysis.threat_intelligence.risk if state.analysis.threat_intelligence else None
            static_risk = state.analysis.static.risk if state.analysis.static else None
            is_threat_safe = threat_risk and threat_risk.score == 0
            is_static_safe = static_risk and static_risk.score == 0

            if is_threat_safe and is_static_safe:
                logger.info("[Orchestrator] Tier 2 Decisive Safe Exit triggered. Bypassing Dynamic & AI analysis.")
                state = await asyncio.to_thread(report_node, state)
                state = await asyncio.to_thread(store_node, state)
                return self._finalize_state(state, url, start_time)

            # 3. Tier 3 check: Sandbox Crawling (Dynamic Analysis)
            if not state.control.should_skip_dynamic:
                state.control.should_retry = True
                while state.control.should_retry and not state.control.should_stop:
                    state = await asyncio.to_thread(dynamic_node, state)
            else:
                logger.info("[Orchestrator] Bypassing Dynamic Sandbox Analysis (should_skip_dynamic = True).")

            # 4. Tier 4 check: Generative AI reasoning
            state = await asyncio.to_thread(ai_node, state)

            # 5. Compilation & Persistence (Phase 6)
            state = await asyncio.to_thread(report_node, state)
            state = await asyncio.to_thread(store_node, state)

        except Exception as e:
            logger.error(f"Fatal Orchestrator Execution crash: {str(e)}", exc_info=True)
            state.workflow.status = ExecutionStatus.FAILED
            
        return self._finalize_state(state, url, start_time)

    def _finalize_state(self, state: URLAnalysisState, url: str, start_time: datetime) -> URLAnalysisState:
        end_time = datetime.utcnow()
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
        return state

    @staticmethod
    def print_execution_summary(state: URLAnalysisState) -> str:
        """Returns a cleanly formatted summary box of the workflow execution metrics and logs it."""
        summary = f"""
========================================
           Execution Summary            
========================================
Request ID:      {state.execution.request_id}
Visited Nodes:   {[n.value for n in state.workflow.visited_nodes]}
Completed Nodes: {[n.value for n in state.workflow.completed_nodes]}
Duration:        {state.execution.duration:.2f}s
Errors:          {len(state.telemetry.errors)}
Warnings:        {len(state.telemetry.warnings)}
Status:          {state.workflow.status.value}
========================================
"""
        logger.info(summary)
        return summary


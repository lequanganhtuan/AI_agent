import logging
from datetime import datetime, timezone
from src.agents.state import URLAnalysisState, ExecutionStatus, NodeName
from src.agents.graph.compile import build_graph

logger = logging.getLogger(__name__)

class AgentRunner:
    """Unified entry point for managing agent execution, lifecycle, and observability."""
    
    def __init__(self):
        self.graph = build_graph()

    def run(self, url: str, cache_hit: bool = False) -> URLAnalysisState:
        """Executes the analysis workflow end-to-end for a URL."""
        start_time = datetime.utcnow()
        
        from src.agents.state.state import create_initial_state
        state = create_initial_state(url)
        state.execution.started_at = start_time
        if cache_hit:
            state.control.cache_hit = True
            
        logger.info(f"=== Starting Agent Execution Workflow ===")
        logger.info(f"Request ID:  {state.execution.request_id}")
        logger.info(f"URL:         {url}")
        logger.info(f"Start Time:  {start_time.isoformat()}")

        try:
            final_state_raw = self.graph.invoke(state)
            if isinstance(final_state_raw, dict):
                final_state = URLAnalysisState.model_validate(final_state_raw)
            else:
                final_state = final_state_raw
        except Exception as e:
            logger.error(f"Fatal Graph Invocation crash: {str(e)}")
            state.workflow.status = ExecutionStatus.FAILED
            final_state = state

        end_time = datetime.utcnow()
        final_state.execution.finished_at = end_time
        duration = (end_time - start_time).total_seconds()
        final_state.execution.duration = duration

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
        final_state.telemetry.total_nodes = len(all_nodes)
        final_state.telemetry.successful_nodes = len(final_state.workflow.completed_nodes)
        final_state.telemetry.failed_nodes = len(final_state.telemetry.errors)
        final_state.telemetry.skipped_nodes = len(all_nodes) - len(final_state.workflow.visited_nodes)

        # Log complete execution telemetry
        risk_level = "UNKNOWN"
        if final_state.report and final_state.report.threat_intelligence and final_state.report.threat_intelligence.risk:
            risk_level = final_state.report.threat_intelligence.risk.risk_level.upper()
        elif final_state.analysis.threat_intelligence and final_state.analysis.threat_intelligence.risk:
            risk_level = final_state.analysis.threat_intelligence.risk.risk_level.upper()

        logger.info(f"=== Agent Execution Workflow Complete ===")
        logger.info(f"Request ID:   {final_state.execution.request_id}")
        logger.info(f"URL:          {url}")
        logger.info(f"End Time:     {end_time.isoformat()}")
        logger.info(f"Duration:     {duration:.2f}s")
        logger.info(f"Final Status: {final_state.workflow.status.value}")
        logger.info(f"Risk Level:   {risk_level}")
        logger.info(f"Cache Hit:    {final_state.control.cache_hit}")

        self.print_execution_summary(final_state)
        return final_state

    @staticmethod
    def print_execution_summary(state: URLAnalysisState) -> None:
        """Outputs a cleanly formatted summary box of the workflow execution metrics."""
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
        print(summary)

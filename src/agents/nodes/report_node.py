import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry

logger = logging.getLogger(__name__)

def report_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing report_node")
    state.workflow.current_node = NodeName.REPORT
    state.workflow.visited_nodes.append(NodeName.REPORT)
    
    tool = tool_registry.get(NodeName.REPORT)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.REPORT)] = result.duration
    
    if result.success:
        state.report = result.data
        state.workflow.completed_nodes.append(NodeName.REPORT)
    else:
        state.control.should_stop = True
        state.workflow.status = ExecutionStatus.FAILED
        
        err = AgentError(
            node=str(NodeName.REPORT),
            tool="ReportTool",
            message=result.error or "Unknown ReportTool failure",
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable
        )
        state.telemetry.errors.append(err)
        
    return state

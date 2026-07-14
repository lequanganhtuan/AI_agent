import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools.static_tool import StaticTool

logger = logging.getLogger(__name__)

def static_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing static_node")
    state.workflow.current_node = NodeName.STATIC
    state.workflow.visited_nodes.append(NodeName.STATIC)
    
    tool = StaticTool()
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.STATIC)] = result.duration
    
    if result.success:
        state.analysis.static = result.data
        state.workflow.completed_nodes.append(NodeName.STATIC)
    else:
        state.control.should_stop = True
        state.workflow.status = ExecutionStatus.FAILED
        
        err = AgentError(
            node=str(NodeName.STATIC),
            tool="StaticTool",
            message=result.error or "Unknown StaticTool failure",
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable
        )
        state.telemetry.errors.append(err)
        
    return state

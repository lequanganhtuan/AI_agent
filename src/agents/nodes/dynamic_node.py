import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools.dynamic_tool import DynamicTool

logger = logging.getLogger(__name__)

def dynamic_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing dynamic_node")
    state.workflow.current_node = NodeName.DYNAMIC
    state.workflow.visited_nodes.append(NodeName.DYNAMIC)
    
    tool = DynamicTool()
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.DYNAMIC)] = result.duration
    
    if result.success:
        state.analysis.dynamic = result.data
        state.control.should_retry = False
        state.workflow.completed_nodes.append(NodeName.DYNAMIC)
    else:
        # Check retry limit (max 3 attempts)
        max_retries = 3
        if result.retryable and state.execution.retry_count < max_retries:
            state.execution.retry_count += 1
            state.control.should_retry = True
            logger.warning(f"DynamicTool failed. Registering retry attempt {state.execution.retry_count}/{max_retries}")
        else:
            state.control.should_retry = False
            err = AgentError(
                node=str(NodeName.DYNAMIC),
                tool="DynamicTool",
                message=result.error or "DynamicTool failed after max retries",
                exception_type="ToolExecutionError",
                timestamp=datetime.utcnow(),
                retryable=result.retryable
            )
            state.telemetry.errors.append(err)
            state.telemetry.warnings.append(f"Dynamic analysis failed and fallback was triggered: {result.error}")
            
    return state

import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

logger = logging.getLogger(__name__)

def dynamic_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing dynamic_node")
    state.workflow.current_node = NodeName.DYNAMIC
    state.workflow.visited_nodes.append(NodeName.DYNAMIC)
    
    tool = tool_registry.get(NodeName.DYNAMIC)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.DYNAMIC)] = result.duration
    
    if result.success:
        state.analysis.dynamic = result.data
        state.control.should_retry = False
        state.workflow.completed_nodes.append(NodeName.DYNAMIC)
    else:
        err_msg = result.error or "Unknown DynamicTool failure"
        decision = error_policy.handle(err_msg, NodeName.DYNAMIC, state.execution.retry_count, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        state.control.should_retry = (decision.action == ErrorAction.RETRY)
        
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
        elif decision.action == ErrorAction.RETRY:
            state.execution.retry_count += 1
            logger.warning(f"DynamicTool retry scheduled. Attempt {state.execution.retry_count}")
            
        err = AgentError(
            node=str(NodeName.DYNAMIC),
            tool="DynamicTool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"Dynamic node error handled with {decision.action}: {err_msg}")
        
    return state

import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

logger = logging.getLogger(__name__)

def static_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing static_node")
    state.workflow.current_node = NodeName.STATIC
    state.workflow.visited_nodes.append(NodeName.STATIC)
    
    tool = tool_registry.get(NodeName.STATIC)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.STATIC)] = result.duration
    
    if result.success:
        state.analysis.static = result.data
        state.workflow.completed_nodes.append(NodeName.STATIC)
    else:
        err_msg = result.error or "Unknown StaticTool failure"
        decision = error_policy.handle(err_msg, NodeName.STATIC, 0, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
            
        err = AgentError(
            node=str(NodeName.STATIC),
            tool="StaticTool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"Static node failed and continued: {err_msg}")
        
    from src.agents.checkpoint import checkpoint_manager
    checkpoint_manager.save(state)
    return state

import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

logger = logging.getLogger(__name__)

def store_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing store_node")
    state.workflow.current_node = NodeName.STORE
    state.workflow.visited_nodes.append(NodeName.STORE)
    
    tool = tool_registry.get(NodeName.STORE)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.STORE)] = result.duration
    
    if result.success:
        state.workflow.completed_nodes.append(NodeName.STORE)
        state.workflow.status = ExecutionStatus.SUCCESS
        state.execution.finished_at = datetime.utcnow()
        if state.execution.started_at:
            delta = state.execution.finished_at - state.execution.started_at
            state.execution.duration = delta.total_seconds()
    else:
        err_msg = result.error or "Unknown StoreTool failure"
        decision = error_policy.handle(err_msg, NodeName.STORE, 0, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
            
        err = AgentError(
            node=str(NodeName.STORE),
            tool="StoreTool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"StoreNode failed and handled with {decision.action}: {err_msg}")
        
    from src.agents.checkpoint import checkpoint_manager
    checkpoint_manager.save(state)
    return state

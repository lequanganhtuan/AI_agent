import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

logger = logging.getLogger(__name__)

def validate_node(state: URLAnalysisState) -> URLAnalysisState:
    logger.info("Executing validate_node")
    state.workflow.current_node = NodeName.VALIDATE
    state.workflow.visited_nodes.append(NodeName.VALIDATE)
    
    tool = tool_registry.get(NodeName.VALIDATE)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.VALIDATE)] = result.duration
    
    if result.success:
        validation_result = result.data
        state.analysis.validation = validation_result
        
        if validation_result and validation_result.valid:
            state.analysis.normalized_url = validation_result.normalized_url
            state.workflow.completed_nodes.append(NodeName.VALIDATE)
        else:
            err_msg = (validation_result.error_message if validation_result else "") or "URL validation returned invalid status"
            decision = error_policy.handle(err_msg, NodeName.VALIDATE, 0, False)
            
            state.control.should_stop = (decision.action == ErrorAction.STOP)
            if decision.action == ErrorAction.STOP:
                state.workflow.status = ExecutionStatus.FAILED
                
            err = AgentError(
                node=str(NodeName.VALIDATE),
                tool="ValidateTool",
                message=err_msg,
                exception_type="ValidationError",
                timestamp=datetime.utcnow(),
                retryable=False,
                error_type=decision.error_type,
                action_taken=str(decision.action)
            )
            state.telemetry.errors.append(err)
            state.telemetry.warnings.append(f"Validation failure: {err_msg}")
    else:
        err_msg = result.error or "Unknown ValidateTool failure"
        decision = error_policy.handle(err_msg, NodeName.VALIDATE, 0, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
            
        err = AgentError(
            node=str(NodeName.VALIDATE),
            tool="ValidateTool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        
    from src.agents.checkpoint import checkpoint_manager
    checkpoint_manager.save(state)
    return state

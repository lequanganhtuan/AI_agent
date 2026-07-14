import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools.validate_tool import ValidateTool

logger = logging.getLogger(__name__)

def validate_node(state: URLAnalysisState) -> URLAnalysisState:
    logger.info("Executing validate_node")
    state.workflow.current_node = NodeName.VALIDATE
    state.workflow.visited_nodes.append(NodeName.VALIDATE)
    
    tool = ValidateTool()
    result = tool.run(state)
    
    # Store performance timing
    state.telemetry.node_timings[str(NodeName.VALIDATE)] = result.duration
    
    if result.success:
        validation_result = result.data
        state.analysis.validation = validation_result
        
        if validation_result and validation_result.valid:
            state.analysis.normalized_url = validation_result.normalized_url
            state.workflow.completed_nodes.append(NodeName.VALIDATE)
        else:
            state.control.should_stop = True
            state.workflow.status = ExecutionStatus.FAILED
            if validation_result and validation_result.error_message:
                state.telemetry.warnings.append(
                    f"URL Validation failed: {validation_result.error_message}"
                )
    else:
        state.control.should_stop = True
        state.workflow.status = ExecutionStatus.FAILED
        
        err = AgentError(
            node=str(NodeName.VALIDATE),
            tool="ValidateTool",
            message=result.error or "Unknown ValidateTool failure",
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable
        )
        state.telemetry.errors.append(err)
        
    return state

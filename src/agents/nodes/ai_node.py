import logging
from datetime import datetime, timezone
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

logger = logging.getLogger(__name__)

async def ai_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing ai_node")
    state.workflow.current_node = NodeName.AI
    state.workflow.visited_nodes.append(NodeName.AI)
    
    tool = tool_registry.get(NodeName.AI)
    result = await tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.AI)] = result.duration
    
    if result.success:
        state.analysis.ai = result.data
        state.workflow.completed_nodes.append(NodeName.AI)
        state.telemetry.provider_requests["Gemini LLM"] = 1
        if result.data and hasattr(result.data, "token_usage") and result.data.token_usage:
            state.telemetry.token_usage.update(result.data.token_usage)
    else:
        err_msg = result.error or "Unknown AITool failure"
        decision = error_policy.handle(err_msg, NodeName.AI, 0, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
            
        err = AgentError(
            node=str(NodeName.AI),
            tool="AITool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.now(timezone.utc),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"AI content analysis failed and handled with {decision.action}: {err_msg}")
        
    from src.agents.checkpoint import checkpoint_manager
    checkpoint_manager.save(state)
    return state

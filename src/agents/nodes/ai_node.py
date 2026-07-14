import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry

logger = logging.getLogger(__name__)

def ai_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing ai_node")
    state.workflow.current_node = NodeName.AI
    state.workflow.visited_nodes.append(NodeName.AI)
    
    tool = tool_registry.get(NodeName.AI)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.AI)] = result.duration
    
    if result.success:
        state.analysis.ai = result.data
        state.workflow.completed_nodes.append(NodeName.AI)
    else:
        # Log failure, but DO NOT halt downstream nodes (report, store)
        err = AgentError(
            node=str(NodeName.AI),
            tool="AITool",
            message=result.error or "AITool failed",
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"AI content analysis failed: {result.error}")
        
    return state

import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools.threat_tool import ThreatTool

logger = logging.getLogger(__name__)

def threat_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing threat_node")
    state.workflow.current_node = NodeName.THREAT
    state.workflow.visited_nodes.append(NodeName.THREAT)
    
    tool = ThreatTool()
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.THREAT)] = result.duration
    
    if result.success:
        state.analysis.threat_intelligence = result.data
        state.workflow.completed_nodes.append(NodeName.THREAT)
    else:
        state.control.should_stop = True
        state.workflow.status = ExecutionStatus.FAILED
        
        err = AgentError(
            node=str(NodeName.THREAT),
            tool="ThreatTool",
            message=result.error or "Unknown ThreatTool failure",
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable
        )
        state.telemetry.errors.append(err)
        
    return state

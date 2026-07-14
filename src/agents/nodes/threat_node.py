import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry

logger = logging.getLogger(__name__)

def threat_node(state: URLAnalysisState) -> URLAnalysisState:
    if state.control.should_stop:
        return state

    logger.info("Executing threat_node")
    state.workflow.current_node = NodeName.THREAT
    state.workflow.visited_nodes.append(NodeName.THREAT)
    
    tool = tool_registry.get(NodeName.THREAT)
    result = tool.run(state)
    
    state.telemetry.node_timings[str(NodeName.THREAT)] = result.duration
    
    if result.success:
        state.analysis.threat_intelligence = result.data
        state.workflow.completed_nodes.append(NodeName.THREAT)
        
        # Update should_skip_dynamic flag if risk level is high or score is high
        if result.data and result.data.risk:
            if result.data.risk.risk_level.upper() in ("HIGH", "CRITICAL", "MALICIOUS") or result.data.risk.score >= 70:
                state.control.should_skip_dynamic = True
                logger.info("Threat intelligence detected high risk. Setting should_skip_dynamic = True")
            else:
                state.control.should_skip_dynamic = False
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

import logging
from datetime import datetime
from src.agents.state import URLAnalysisState, NodeName, ExecutionStatus, AgentError
from src.agents.tools import tool_registry
from src.agents.error import error_policy, ErrorAction

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
        err_msg = result.error or "Unknown ThreatTool failure"
        decision = error_policy.handle(err_msg, NodeName.THREAT, 0, result.retryable)
        
        state.control.should_stop = (decision.action == ErrorAction.STOP)
        if decision.action == ErrorAction.STOP:
            state.workflow.status = ExecutionStatus.FAILED
            
        err = AgentError(
            node=str(NodeName.THREAT),
            tool="ThreatTool",
            message=err_msg,
            exception_type="ToolExecutionError",
            timestamp=datetime.utcnow(),
            retryable=result.retryable,
            error_type=decision.error_type,
            action_taken=str(decision.action)
        )
        state.telemetry.errors.append(err)
        state.telemetry.warnings.append(f"Threat node failed and continued: {err_msg}")
        
    return state

import logging
from src.agents.state import URLAnalysisState, NodeName

logger = logging.getLogger(__name__)

def merge_node(state: URLAnalysisState) -> URLAnalysisState:
    """Administrative sync node that runs after Static and Threat nodes complete."""
    logger.info("Executing merge_node (synchronization point)")
    state.workflow.current_node = NodeName.MERGE
    state.workflow.visited_nodes.append(NodeName.MERGE)
    state.workflow.completed_nodes.append(NodeName.MERGE)
    from src.agents.checkpoint import checkpoint_manager
    checkpoint_manager.save(state)
    return state

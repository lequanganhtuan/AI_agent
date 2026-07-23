import logging
from datetime import datetime, timezone
from typing import Dict, Any
from .base import BaseCheckpointSaver
from src.agents.state import URLAnalysisState

logger = logging.getLogger(__name__)

class InMemoryCheckpointSaver(BaseCheckpointSaver):
    """In-memory implementation of the state checkpoint storage."""
    
    def __init__(self):
        # Maps request_id -> latest URLAnalysisState snapshot
        self._storage: Dict[str, URLAnalysisState] = {}

    def save(self, state: URLAnalysisState) -> None:
        request_id = state.execution.request_id
        
        # Update persistence telemetry metadata inside the state
        state.telemetry.checkpoint_saved = True
        state.telemetry.checkpoint_id = request_id
        state.telemetry.checkpoint_time = datetime.now(timezone.utc)
        
        # Deep clone/serialize to avoid mutations affecting stored checkpoints
        from src.agents.state.state import clone_state
        cloned = clone_state(state)
        
        self._storage[request_id] = cloned
        logger.info(f"[CheckpointManager] Saved checkpoint for request {request_id} at node {state.workflow.current_node}")

    def load(self, request_id: str) -> URLAnalysisState:
        checkpoint = self._storage.get(request_id)
        if not checkpoint:
            raise KeyError(f"No checkpoint found for request ID: {request_id}")
        
        from src.agents.state.state import clone_state
        return clone_state(checkpoint)

    def delete(self, request_id: str) -> None:
        if request_id in self._storage:
            del self._storage[request_id]
            logger.info(f"[CheckpointManager] Deleted checkpoint for request {request_id}")
        else:
            logger.warning(f"[CheckpointManager] Attempted to delete non-existent checkpoint for request {request_id}")

# Global checkpoint instance
checkpoint_manager = InMemoryCheckpointSaver()

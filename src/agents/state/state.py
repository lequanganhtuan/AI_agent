from copy import deepcopy
from .url_analysis_state import URLAnalysisState
from .enums import ExecutionStatus, NodeName

def create_initial_state(raw_url: str) -> URLAnalysisState:
    """Creates a new initial URLAnalysisState instance with raw_url populated."""
    state = URLAnalysisState()
    state.analysis.raw_url = raw_url
    state.workflow.status = ExecutionStatus.PENDING
    state.workflow.current_node = NodeName.INIT
    return state

def clone_state(state: URLAnalysisState) -> URLAnalysisState:
    """Creates a deep copy of the current state instance."""
    return deepcopy(state)

def load_state(data: dict) -> URLAnalysisState:
    """Loads a URLAnalysisState instance from a dictionary structure."""
    return URLAnalysisState.model_validate(data)

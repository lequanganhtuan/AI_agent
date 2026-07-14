import logging
from typing import Union, List
from src.agents.state import URLAnalysisState

logger = logging.getLogger(__name__)

def route_after_validate(state: URLAnalysisState) -> Union[str, List[str]]:
    """Decides to stop if invalid, jump to report if cache hit, or run parallel checks."""
    if state.control.should_stop:
        logger.info("[Router: Validate] URL is invalid. Routing to END.")
        return "end"
    if state.control.cache_hit:
        logger.info("[Router: Validate] Cache hit detected. Bypassing analysis, routing to REPORT.")
        return "report"
    logger.info("[Router: Validate] URL is valid. Forking to parallel STATIC and THREAT branches.")
    return ["static", "threat"]

def route_after_merge(state: URLAnalysisState) -> str:
    """Bypasses dynamic browser check if parallel threat intel reported high phishing risks."""
    if state.control.should_stop:
        logger.info("[Router: Merge] should_stop set. Routing to END.")
        return "end"
    if state.control.should_skip_dynamic:
        logger.info("[Router: Merge] High threat flag active. Skipping dynamic analysis, routing to AI.")
        return "ai"
    logger.info("[Router: Merge] Routing to DYNAMIC.")
    return "dynamic"

def route_after_dynamic(state: URLAnalysisState) -> str:
    """Decides to retry dynamic analysis or proceed to AI content analysis."""
    if state.control.should_retry:
        logger.info("[Router: Dynamic] Transient failure detected. Routing to retry DYNAMIC.")
        return "dynamic"
    logger.info("[Router: Dynamic] Proceeding/falling back to AI.")
    return "ai"

def route_after_ai(state: URLAnalysisState) -> str:
    """Ensures errors in the AI node do not crash the workflow."""
    logger.info("[Router: AI] Bypassing AI failures if any, routing to REPORT.")
    return "report"

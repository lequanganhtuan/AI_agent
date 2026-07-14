import logging
from src.agents.state import URLAnalysisState

logger = logging.getLogger(__name__)

def route_after_validate(state: URLAnalysisState) -> str:
    """Decides to stop if invalid, jump to report if cache hit, or run static checks."""
    if state.control.should_stop:
        logger.info("[Router: Validate] URL is invalid. Routing to END.")
        return "end"
    if state.control.cache_hit:
        logger.info("[Router: Validate] Cache hit detected. Bypassing analysis, routing to REPORT.")
        return "report"
    logger.info("[Router: Validate] URL is valid. Routing to STATIC.")
    return "static"

def route_after_threat(state: URLAnalysisState) -> str:
    """Skips dynamic browser checks if threat intelligence reports high-risk phishing."""
    if state.control.should_stop:
        logger.info("[Router: Threat] should_stop set. Routing to END.")
        return "end"
    if state.control.should_skip_dynamic:
        logger.info("[Router: Threat] High threat flag active. Bypassing dynamic check, routing directly to AI.")
        return "ai"
    logger.info("[Router: Threat] Threat score low. Routing to DYNAMIC.")
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

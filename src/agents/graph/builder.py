from langgraph.graph import StateGraph, START, END
from src.agents.state import URLAnalysisState
from src.agents.nodes import (
    validate_node,
    static_node,
    threat_node,
    dynamic_node,
    ai_node,
    report_node,
    store_node
)
from .routes import (
    route_after_validate,
    route_after_threat,
    route_after_dynamic,
    route_after_ai
)

def create_graph_builder() -> StateGraph:
    """Builds the StateGraph using conditional routing rules."""
    builder = StateGraph(URLAnalysisState)
    
    # 1. Register all nodes
    builder.add_node("validate", validate_node)
    builder.add_node("static", static_node)
    builder.add_node("threat", threat_node)
    builder.add_node("dynamic", dynamic_node)
    builder.add_node("ai", ai_node)
    builder.add_node("report", report_node)
    builder.add_node("store", store_node)
    
    # 2. Add linear entry and simple nodes transitions
    builder.add_edge(START, "validate")
    builder.add_edge("static", "threat")
    builder.add_edge("report", "store")
    builder.add_edge("store", END)
    
    # 3. Add conditional routing edges
    builder.add_conditional_edges(
        "validate",
        route_after_validate,
        {
            "static": "static",
            "report": "report",
            "end": END
        }
    )
    
    builder.add_conditional_edges(
        "threat",
        route_after_threat,
        {
            "dynamic": "dynamic",
            "ai": "ai",
            "end": END
        }
    )
    
    builder.add_conditional_edges(
        "dynamic",
        route_after_dynamic,
        {
            "dynamic": "dynamic",
            "ai": "ai"
        }
    )
    
    builder.add_conditional_edges(
        "ai",
        route_after_ai,
        {
            "report": "report"
        }
    )
    
    return builder

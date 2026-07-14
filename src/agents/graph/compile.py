import os
import logging
from typing import Any
from .builder import create_graph_builder

logger = logging.getLogger(__name__)

def build_graph() -> Any:
    """Compiles the StateGraph and attempts to output visualization assets."""
    builder = create_graph_builder()
    compiled = builder.compile()
    
    # Export visualization elements
    _export_graph_visualization(compiled)
    
    return compiled

def _export_graph_visualization(compiled: Any):
    try:
        # Create artifacts folder if missing
        os.makedirs("artifacts", exist_ok=True)
        
        # 1. Save Mermaid diagram string
        mermaid_code = compiled.get_graph().draw_mermaid()
        with open("artifacts/graph_skeleton.md", "w", encoding="utf-8") as f:
            f.write("```mermaid\n" + mermaid_code + "\n```")
        logger.info("Saved graph Mermaid diagram to artifacts/graph_skeleton.md")
        
        # 2. Draw graph PNG (if Graphviz/Pygraphviz is installed)
        png_bytes = compiled.get_graph().draw_mermaid_png()
        with open("artifacts/graph_skeleton.png", "wb") as f:
            f.write(png_bytes)
        logger.info("Saved graph visualization to artifacts/graph_skeleton.png")
    except Exception as e:
        logger.warning(f"Could not render graph visualization image (possibly missing Graphviz): {str(e)}")

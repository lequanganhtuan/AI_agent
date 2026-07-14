import os
import base64
import logging
import requests
from src.agents.graph.compile import build_graph

# Configure basic logging to stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def export_svg():
    """Compiles the StateGraph and queries mermaid.ink to save the SVG diagram visualization."""
    logger.info("Compiling graph structure...")
    compiled = build_graph()
    
    logger.info("Reading Mermaid markup...")
    mermaid_code = compiled.get_graph().draw_mermaid()
    
    os.makedirs("artifacts", exist_ok=True)
    
    # Base64 encode the mermaid markup code
    logger.info("Requesting SVG diagram from mermaid.ink...")
    try:
        payload = base64.b64encode(mermaid_code.encode("utf-8")).decode("ascii")
        url = f"https://mermaid.ink/svg/{payload}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            output_path = "artifacts/graph_skeleton.svg"
            with open(output_path, "wb") as f:
                f.write(response.content)
            logger.info(f"Successfully saved SVG visualization diagram to {output_path}")
        else:
            logger.error(f"Failed to fetch SVG. HTTP status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to export graph SVG visualization: {str(e)}")

if __name__ == "__main__":
    export_svg()

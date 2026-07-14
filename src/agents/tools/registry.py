from typing import Dict, Union
from src.agents.state.enums import NodeName
from src.agents.tools.base import BaseTool
from src.agents.tools.validate_tool import ValidateTool
from src.agents.tools.static_tool import StaticTool
from src.agents.tools.threat_tool import ThreatTool
from src.agents.tools.dynamic_tool import DynamicTool
from src.agents.tools.ai_tool import AITool
from src.agents.tools.report_tool import ReportTool
from src.agents.tools.store_tool import StoreTool

class ToolRegistry:
    """Centralized registry and Dependency Injection container for Agent Tools."""
    
    def __init__(self):
        # Initialize stateless tools as singletons
        self._tools: Dict[str, BaseTool] = {
            "validate": ValidateTool(),
            "static": StaticTool(),
            "threat": ThreatTool(),
            "dynamic": DynamicTool(),
            "ai": AITool(),
            "report": ReportTool(),
            "store": StoreTool(),
        }

    def get(self, key: Union[NodeName, str]) -> BaseTool:
        """Retrieves the tool associated with the node key (case-insensitive)."""
        if isinstance(key, NodeName):
            norm_key = key.value.lower()
        else:
            norm_key = str(key).lower()
            
        tool = self._tools.get(norm_key)
        if not tool:
            raise KeyError(f"No tool registered for node name key: '{key}'")
        return tool

# Global singleton instance
tool_registry = ToolRegistry()

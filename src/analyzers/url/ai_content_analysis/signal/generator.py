from typing import List
from src.analyzers.url.ai_content_analysis.models import ContentAnalysisResult, AISignal
from src.analyzers.url.ai_content_analysis.signal.mapper import AISignalMapper

class AISignalGenerator:
    """Orchestrator that converts ContentAnalysisResult into a list of AISignal objects.
    
    This class is strictly dedicated to coordination and contains no internal business rules.
    """
    
    def __init__(self, mapper: AISignalMapper) -> None:
        self.mapper = mapper

    def generate(self, result: ContentAnalysisResult) -> List[AISignal]:
        """Orchestrates the mapping from ContentAnalysisResult to list of AISignal."""
        return self.mapper.map_signals(result)

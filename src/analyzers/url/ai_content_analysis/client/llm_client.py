from abc import ABC, abstractmethod
from src.analyzers.url.ai_content_analysis.models import PromptRequest

class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(self, request: PromptRequest) -> str:
        """Asynchronously sends a PromptRequest to the language model and returns the raw string response.
        
        This abstract method must be implemented by concrete clients (e.g. OpenAIClient).
        """
        pass

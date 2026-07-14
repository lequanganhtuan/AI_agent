from abc import ABC, abstractmethod
from typing import Any

class BaseCheckpointSaver(ABC):
    """Abstract base class defining the persistence interface for state checkpoints."""
    
    @abstractmethod
    def save(self, state: Any) -> None:
        """Persists the state checkpoint."""
        pass

    @abstractmethod
    def load(self, request_id: str) -> Any:
        """Retrieves a persisted state checkpoint by its request ID."""
        pass

    @abstractmethod
    def delete(self, request_id: str) -> None:
        """Deletes a persisted state checkpoint."""
        pass

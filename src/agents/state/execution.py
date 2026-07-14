import uuid
from datetime import datetime
from pydantic import BaseModel, Field

class ExecutionState(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    duration: float = 0.0
    retry_count: int = 0

from datetime import datetime
from pydantic import BaseModel, Field

class AgentError(BaseModel):
    node: str
    tool: str | None = None
    message: str
    exception_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retryable: bool
    error_type: str | None = None
    action_taken: str | None = None

class TelemetryState(BaseModel):
    errors: list[AgentError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    node_metrics: dict = Field(default_factory=dict)
    node_timings: dict[str, float] = Field(default_factory=dict)
    checkpoint_saved: bool = False
    checkpoint_id: str | None = None
    checkpoint_time: datetime | None = None
    total_nodes: int = 0
    successful_nodes: int = 0
    failed_nodes: int = 0
    skipped_nodes: int = 0

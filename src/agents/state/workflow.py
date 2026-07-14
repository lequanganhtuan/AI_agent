from pydantic import BaseModel, Field
from .enums import ExecutionStatus, NodeName

class WorkflowState(BaseModel):
    current_node: NodeName = NodeName.INIT
    next_node: NodeName | None = None
    visited_nodes: list[NodeName] = Field(default_factory=list)
    completed_nodes: list[NodeName] = Field(default_factory=list)
    status: ExecutionStatus = ExecutionStatus.PENDING

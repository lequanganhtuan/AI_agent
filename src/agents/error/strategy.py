from enum import Enum
from pydantic import BaseModel

class ErrorAction(str, Enum):
    RETRY = "RETRY"
    CONTINUE = "CONTINUE"
    SKIP = "SKIP"
    STOP = "STOP"

class ErrorDecision(BaseModel):
    action: ErrorAction
    error_type: str
    message: str

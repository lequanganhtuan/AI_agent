from enum import Enum

class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    FAILED = "failed"
    SUCCESS = "success"
    CANCELLED = "cancelled"

class NodeName(str, Enum):
    INIT = "INIT"
    VALIDATE = "VALIDATE"
    STATIC = "STATIC"
    THREAT = "THREAT"
    MERGE = "MERGE"
    DYNAMIC = "DYNAMIC"
    AI = "AI"
    REPORT = "REPORT"
    STORE = "STORE"

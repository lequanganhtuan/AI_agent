from pydantic import BaseModel, Field
from src.core.report.fraud_report import FraudReport
from .analysis import AnalysisState
from .workflow import WorkflowState
from .control import ControlState
from .execution import ExecutionState
from .telemetry import TelemetryState

class URLAnalysisState(BaseModel):
    analysis: AnalysisState = Field(default_factory=AnalysisState)
    workflow: WorkflowState = Field(default_factory=WorkflowState)
    control: ControlState = Field(default_factory=ControlState)
    execution: ExecutionState = Field(default_factory=ExecutionState)
    telemetry: TelemetryState = Field(default_factory=TelemetryState)
    report: FraudReport | None = None

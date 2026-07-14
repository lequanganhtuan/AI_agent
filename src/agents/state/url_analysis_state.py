from typing import Annotated, Any
from pydantic import BaseModel, Field
from src.core.report.fraud_report import FraudReport
from .analysis import AnalysisState
from .workflow import WorkflowState
from .control import ControlState
from .execution import ExecutionState
from .telemetry import TelemetryState

def merge_analysis(left: Any, right: Any) -> Any:
    if not left: return right
    if not right: return left
    for field in ["raw_url", "normalized_url", "final_url", "validation", "static", "threat_intelligence", "dynamic", "ai"]:
        val = getattr(right, field, None)
        if val is not None:
            setattr(left, field, val)
    return left

def merge_workflow(left: Any, right: Any) -> Any:
    if not left: return right
    if not right: return left
    if right.current_node and right.current_node != "INIT":
        left.current_node = right.current_node
    # Merge visited and completed lists maintaining order
    for node in right.visited_nodes:
        if node not in left.visited_nodes:
            left.visited_nodes.append(node)
    for node in right.completed_nodes:
        if node not in left.completed_nodes:
            left.completed_nodes.append(node)
    if right.status and right.status != "pending":
        left.status = right.status
    return left

def merge_control(left: Any, right: Any) -> Any:
    if not left: return right
    if not right: return left
    if right.should_stop:
        left.should_stop = True
    if right.should_skip_dynamic:
        left.should_skip_dynamic = True
    if right.should_retry:
        left.should_retry = True
    if right.cache_hit:
        left.cache_hit = True
    return left

def merge_execution(left: Any, right: Any) -> Any:
    if not left: return right
    if not right: return left
    if right.started_at:
        left.started_at = right.started_at
    if right.finished_at:
        left.finished_at = right.finished_at
    if right.duration:
        left.duration = right.duration
    if right.retry_count > left.retry_count:
        left.retry_count = right.retry_count
    return left

def merge_telemetry(left: Any, right: Any) -> Any:
    if not left: return right
    if not right: return left
    if right.node_timings:
        left.node_timings.update(right.node_timings)
    for err in right.errors:
        if err not in left.errors:
            left.errors.append(err)
    for warn in right.warnings:
        if warn not in left.warnings:
            left.warnings.append(warn)
    return left

class URLAnalysisState(BaseModel):
    analysis: Annotated[AnalysisState, merge_analysis] = Field(default_factory=AnalysisState)
    workflow: Annotated[WorkflowState, merge_workflow] = Field(default_factory=WorkflowState)
    control: Annotated[ControlState, merge_control] = Field(default_factory=ControlState)
    execution: Annotated[ExecutionState, merge_execution] = Field(default_factory=ExecutionState)
    telemetry: Annotated[TelemetryState, merge_telemetry] = Field(default_factory=TelemetryState)
    report: FraudReport | None = None

import pytest
from typing import Any
from src.agents.runner import AgentRunner
from src.agents.state import ExecutionStatus, NodeName
from src.agents.tools import tool_registry, BaseTool, ToolResult
from src.core.models import DynamicAnalysisResult

@pytest.fixture(autouse=True)
def restore_registry_tools():
    """Fixture to ensure the global tool registry is reset back to original state after each test."""
    original_tools = dict(tool_registry._tools)
    yield
    tool_registry._tools = original_tools

def test_valid_url_path():
    """E2E Smoke Test 1: Valid URL execution traversal completes successfully."""
    runner = AgentRunner()
    # Runs the standard success path (no cache hit, valid URL format)
    state = runner.run("https://example.com")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS
    # Check that it traversed all standard nodes: validate, static, threat, merge, dynamic, ai, report, store
    visited = state.workflow.visited_nodes
    assert NodeName.VALIDATE in visited
    assert NodeName.STATIC in visited
    assert NodeName.THREAT in visited
    assert NodeName.MERGE in visited
    assert NodeName.DYNAMIC in visited
    assert NodeName.AI in visited
    assert NodeName.REPORT in visited
    assert NodeName.STORE in visited
    
    # Assert telemetry metrics are computed and matched correctly
    assert state.telemetry.total_nodes == 8
    assert state.telemetry.successful_nodes == len(state.workflow.completed_nodes)
    assert state.telemetry.failed_nodes == 0
    assert state.telemetry.skipped_nodes == 0

def test_invalid_url_path():
    """E2E Smoke Test 2: Invalid URL format halts workflow immediately after validation."""
    runner = AgentRunner()
    state = runner.run("invalid")
    
    assert state.workflow.status == ExecutionStatus.FAILED
    assert state.workflow.visited_nodes == [NodeName.VALIDATE]
    assert state.control.should_stop is True
    
    assert state.telemetry.total_nodes == 8
    assert state.telemetry.successful_nodes == 0
    assert state.telemetry.failed_nodes >= 1
    assert state.telemetry.skipped_nodes == 7

def test_cache_hit_path():
    """E2E Smoke Test 3: Cache Hit bypasses static, threat, merge, dynamic, and AI nodes."""
    runner = AgentRunner()
    state = runner.run("https://cached-site.org", cache_hit=True)
    
    assert state.workflow.status == ExecutionStatus.SUCCESS
    # Cache hit should route VALIDATE -> REPORT -> STORE -> END
    assert state.workflow.visited_nodes == [
        NodeName.VALIDATE,
        NodeName.REPORT,
        NodeName.STORE
    ]
    assert state.control.cache_hit is True
    assert state.telemetry.skipped_nodes == 5

def test_dynamic_retry_path():
    """E2E Smoke Test 4: Verifies the workflow retry mechanism under transient dynamic failures."""
    runner = AgentRunner()
    
    class MockTransientFailDynamicTool(BaseTool):
        def __init__(self):
            self.calls = 0
        def _execute(self, state) -> Any:
            pass
        def run(self, state):
            self.calls += 1
            if self.calls == 1:
                # First run fails with a retryable transient error
                return ToolResult(success=False, error="Transient Connection Timeout", retryable=True, duration=0.05)
            else:
                # Succeed on retry
                return ToolResult(success=True, data=DynamicAnalysisResult(), duration=0.05)

    # Register the transient failure mock tool in the registry
    mock_tool = MockTransientFailDynamicTool()
    tool_registry._tools["dynamic"] = mock_tool

    state = runner.run("https://retry-domain.com")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS
    assert mock_tool.calls == 2  # Proves node was run twice
    assert state.execution.retry_count == 1  # Verify state retry counter incremented
    
    # Proves the dynamic node is listed twice in visited (due to retry iteration)
    visited_nodes = state.workflow.visited_nodes
    dynamic_indices = [i for i, node in enumerate(visited_nodes) if node == NodeName.DYNAMIC]
    assert len(dynamic_indices) == 2

def test_ai_node_failure_path():
    """E2E Smoke Test 5: AI failures do not crash execution and yield a final report gracefully."""
    runner = AgentRunner()
    
    class MockFatalFailAITool(BaseTool):
        def _execute(self, state) -> Any:
            pass
        def run(self, state):
            # Fatal error (e.g. quota limit or parsing error)
            return ToolResult(success=False, error="AI service quota exceeded", retryable=False, duration=0.05)

    # Register the mock tool
    tool_registry._tools["ai"] = MockFatalFailAITool()

    state = runner.run("https://ai-fails.net")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS  # Workflow degrades gracefully
    assert NodeName.AI in state.workflow.visited_nodes
    assert NodeName.REPORT in state.workflow.visited_nodes
    assert state.report is not None  # Report generated successfully without AI details
    assert len(state.telemetry.errors) == 1
    assert state.telemetry.errors[0].node == str(NodeName.AI)
    assert state.telemetry.errors[0].error_type == "RateLimitError"

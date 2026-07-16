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

class MockInconclusiveThreatTool(BaseTool):
    def _execute(self, state) -> Any:
        pass
    def run(self, state):
        from src.core.models import ThreatIntelligenceResult, ThreatIntelligenceRisk
        res = ThreatIntelligenceResult(
            risk=ThreatIntelligenceRisk(score=10, risk_level="low", summary="Mock suspicious threat", triggered_signals=["SUSPICIOUS_DOMAIN"]),
            virustotal={},
            google_safe_browsing={},
            urlscan={},
            ip_reputation={},
            urlhaus={"query_status": "no_match"}
        )
        return ToolResult(success=True, data=res, duration=0.05)

def test_valid_url_path():
    """E2E Smoke Test 1: Valid URL execution traversal completes successfully."""
    runner = AgentRunner()
    # Register mock threat tool to make it inconclusive at Tier 2 (proceeding to all nodes)
    tool_registry._tools["threat"] = MockInconclusiveThreatTool()
    
    state = runner.run("https://valid-test-domain.com")
    
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
    tool_registry._tools["threat"] = MockInconclusiveThreatTool()

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
    tool_registry._tools["threat"] = MockInconclusiveThreatTool()

    state = runner.run("https://ai-fails.net")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS  # Workflow degrades gracefully
    assert NodeName.AI in state.workflow.visited_nodes
    assert NodeName.REPORT in state.workflow.visited_nodes
    assert state.report is not None  # Report generated successfully without AI details
    assert len(state.telemetry.errors) == 1
    assert state.telemetry.errors[0].node == str(NodeName.AI)
    assert state.telemetry.errors[0].error_type == "RateLimitError"

def test_whitelist_exit_path():
    """E2E Test: Whitelisted domains trigger immediate active whitelist exit, bypassing other nodes."""
    runner = AgentRunner()
    # "google.com" is whitelisted in SAFE_WHITELIST_DOMAINS
    state = runner.run("https://google.com")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS
    assert state.workflow.visited_nodes == [NodeName.VALIDATE, NodeName.REPORT, NodeName.STORE]
    assert state.control.is_whitelisted is True
    assert state.report is not None
    assert state.report.score == 0
    assert state.report.risk_level == "safe"
    assert state.report.verdict == "ALLOW"
    assert state.report.ai.content.recommended_action == "ALLOW"

def test_suspicious_classification_path():
    """E2E Test: A clean/new domain without prior threat/static indicators gets classified as SUSPICIOUS (score=35)."""
    runner = AgentRunner()
    
    class MockCleanThreatTool(BaseTool):
        def _execute(self, state) -> Any:
            pass
        def run(self, state):
            from src.core.models import ThreatIntelligenceResult, ThreatIntelligenceRisk
            res = ThreatIntelligenceResult(
                risk=ThreatIntelligenceRisk(score=0, risk_level="low", summary="Clean", triggered_signals=[]),
                virustotal={},
                google_safe_browsing={},
                urlscan={},
                ip_reputation={},
                urlhaus={"query_status": "no_match"}
            )
            return ToolResult(success=True, data=res, duration=0.05)

    class MockCleanAITool(BaseTool):
        def _execute(self, state) -> Any:
            pass
        def run(self, state):
            from src.analyzers.url.ai_content_analysis.models import AIAnalysisResult, AIRisk, ContentAnalysisResult, FraudCategory, RecommendedAction, RiskLevel
            res = AIAnalysisResult(
                content=ContentAnalysisResult(
                    website_purpose="Clean site",
                    summary="No threat detected",
                    detected_brand=None,
                    brand_confidence=0.0,
                    fraud_category=FraudCategory.LEGITIMATE,
                    confidence=0.9,
                    reasoning=["No issues."],
                    findings=["All looks good."],
                    recommended_action=RecommendedAction.ALLOW
                ),
                risk=AIRisk(score=0.0, level=RiskLevel.LOW, summary="Clean"),
                signals=[]
            )
            return ToolResult(success=True, data=res, duration=0.05)

    # Register mocks
    tool_registry._tools["threat"] = MockCleanThreatTool()
    tool_registry._tools["ai"] = MockCleanAITool()
    
    state = runner.run("https://new-unseen-domain.com")
    
    assert state.workflow.status == ExecutionStatus.SUCCESS
    assert state.report is not None
    assert state.report.score == 35
    assert state.report.risk_level == "suspicious"
    assert state.report.verdict == "SUSPICIOUS"
    assert state.report.ai.content.recommended_action == "MONITOR"
    assert "no established reputation" in state.report.ai.content.summary.lower()

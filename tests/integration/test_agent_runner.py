import os
import unittest
from typing import Any
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
os.environ["SKIP_LLM_DEV"] = "true"

from src.agents.runner import AgentRunner
from src.agents.state import ExecutionStatus, NodeName
from src.agents.tools import tool_registry, BaseTool, ToolResult
from src.core.models import DynamicAnalysisResult

class MockInconclusiveThreatTool(BaseTool):
    async def _execute(self, state) -> Any:
        pass
    async def run(self, state):
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

class TestAgentRunner(unittest.TestCase):
    def setUp(self):
        self.original_tools = dict(tool_registry._tools)

    def tearDown(self):
        tool_registry._tools = self.original_tools

    def test_valid_url_path(self):
        """E2E Smoke Test 1: Valid URL execution traversal completes successfully."""
        runner = AgentRunner()
        tool_registry._tools["threat"] = MockInconclusiveThreatTool()
        
        state = runner.run("https://valid-test-domain.com")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.SUCCESS)
        visited = state.workflow.visited_nodes
        self.assertIn(NodeName.VALIDATE, visited)
        self.assertIn(NodeName.STATIC, visited)
        self.assertIn(NodeName.THREAT, visited)
        self.assertIn(NodeName.MERGE, visited)
        self.assertIn(NodeName.DYNAMIC, visited)
        self.assertIn(NodeName.AI, visited)
        self.assertIn(NodeName.REPORT, visited)
        self.assertIn(NodeName.STORE, visited)
        
        self.assertEqual(state.telemetry.total_nodes, 8)
        self.assertEqual(state.telemetry.successful_nodes, len(state.workflow.completed_nodes))
        self.assertEqual(state.telemetry.failed_nodes, 0)
        self.assertEqual(state.telemetry.skipped_nodes, 0)

    def test_invalid_url_path(self):
        """E2E Smoke Test 2: Invalid URL format halts workflow immediately after validation."""
        runner = AgentRunner()
        state = runner.run("invalid")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.FAILED)
        self.assertEqual(state.workflow.visited_nodes, [NodeName.VALIDATE])
        self.assertTrue(state.control.should_stop)
        
        self.assertEqual(state.telemetry.total_nodes, 8)
        self.assertEqual(state.telemetry.successful_nodes, 0)
        self.assertGreaterEqual(state.telemetry.failed_nodes, 1)
        self.assertEqual(state.telemetry.skipped_nodes, 7)

    def test_cache_hit_path(self):
        """E2E Smoke Test 3: Cache Hit bypasses static, threat, merge, dynamic, and AI nodes."""
        runner = AgentRunner()
        state = runner.run("https://cached-site.org", cache_hit=True)
        
        self.assertEqual(state.workflow.status, ExecutionStatus.SUCCESS)
        self.assertEqual(state.workflow.visited_nodes, [
            NodeName.VALIDATE,
            NodeName.REPORT,
            NodeName.STORE
        ])
        self.assertTrue(state.control.cache_hit)
        self.assertEqual(state.telemetry.skipped_nodes, 5)

    def test_dynamic_retry_path(self):
        """E2E Smoke Test 4: Verifies the workflow retry mechanism under transient dynamic failures."""
        runner = AgentRunner()
        
        class MockTransientFailDynamicTool(BaseTool):
            def __init__(self):
                self.calls = 0
            async def _execute(self, state) -> Any:
                pass
            async def run(self, state):
                self.calls += 1
                if self.calls == 1:
                    return ToolResult(success=False, error="Transient Connection Timeout", retryable=True, duration=0.05)
                else:
                    return ToolResult(success=True, data=DynamicAnalysisResult(), duration=0.05)

        mock_tool = MockTransientFailDynamicTool()
        tool_registry._tools["dynamic"] = mock_tool
        tool_registry._tools["threat"] = MockInconclusiveThreatTool()

        state = runner.run("https://retry-domain.com")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.SUCCESS)
        self.assertEqual(mock_tool.calls, 2)
        self.assertEqual(state.execution.retry_count, 1)
        
        visited_nodes = state.workflow.visited_nodes
        dynamic_indices = [i for i, node in enumerate(visited_nodes) if node == NodeName.DYNAMIC]
        self.assertEqual(len(dynamic_indices), 2)

    def test_ai_node_failure_path(self):
        """E2E Smoke Test 5: AI failures do not crash execution and yield a final report gracefully."""
        runner = AgentRunner()
        
        class MockFatalFailAITool(BaseTool):
            async def _execute(self, state) -> Any:
                pass
            async def run(self, state):
                return ToolResult(success=False, error="AI service quota exceeded", retryable=False, duration=0.05)

        tool_registry._tools["ai"] = MockFatalFailAITool()
        tool_registry._tools["threat"] = MockInconclusiveThreatTool()

        state = runner.run("https://ai-fails.net")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.FAILED)
        self.assertIn(NodeName.AI, state.workflow.visited_nodes)
        self.assertNotIn(NodeName.REPORT, state.workflow.visited_nodes)
        self.assertIsNone(state.report)
        self.assertEqual(len(state.telemetry.errors), 1)
        self.assertEqual(state.telemetry.errors[0].node, str(NodeName.AI))
        self.assertEqual(state.telemetry.errors[0].error_type, "RateLimitError")

    def test_whitelist_exit_path(self):
        """E2E Test: Whitelisted domains trigger immediate active whitelist exit, bypassing other nodes."""
        runner = AgentRunner()
        state = runner.run("https://google.com")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.SUCCESS)
        self.assertEqual(state.workflow.visited_nodes, [NodeName.VALIDATE, NodeName.REPORT, NodeName.STORE])
        self.assertTrue(state.control.is_whitelisted)
        self.assertIsNotNone(state.report)
        self.assertEqual(state.report.score, 0)
        self.assertEqual(state.report.risk_level, "safe")
        self.assertEqual(state.report.verdict, "ALLOW")
        self.assertEqual(state.report.ai.content.recommended_action, "ALLOW")

    def test_unknown_classification_path(self):
        """E2E Test: A clean/new domain without prior threat/static indicators gets classified as UNKNOWN (score=1)."""
        runner = AgentRunner()
        
        class MockCleanThreatTool(BaseTool):
            async def _execute(self, state) -> Any:
                pass
            async def run(self, state):
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
            async def _execute(self, state) -> Any:
                pass
            async def run(self, state):
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

        tool_registry._tools["threat"] = MockCleanThreatTool()
        tool_registry._tools["ai"] = MockCleanAITool()
        
        state = runner.run("https://new-unseen-domain.com")
        
        self.assertEqual(state.workflow.status, ExecutionStatus.SUCCESS)
        self.assertIsNotNone(state.report)
        self.assertEqual(state.report.score, 1)
        self.assertEqual(state.report.risk_level, "unknown")
        self.assertEqual(state.report.verdict, "UNKNOWN")
        self.assertEqual(state.report.ai.content.recommended_action, "MONITOR")
        self.assertIn("no established reputation", state.report.ai.content.summary.lower())

if __name__ == "__main__":
    unittest.main()

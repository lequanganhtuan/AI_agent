import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.agents.runner import AgentRunner
from src.agents.state import ExecutionStatus
from src.core.models import (
    ThreatIntelligenceResult, ThreatIntelligenceRisk, VirusTotalAnalysis,
    GoogleSafeBrowsingAnalysis, URLScanAnalysis, URLHausAnalysis, AbuseIPDBAnalysis,
    DynamicAnalysisResult, DynamicRisk
)
from src.analyzers.url.ai_content_analysis.models import (
    AIAnalysisResult, ContentAnalysisResult, RecommendedAction, AIRisk, RiskLevel
)

@pytest.mark.anyio
async def test_agent_runner_end_to_end():
    """Test the complete AgentRunner end-to-end execution flow with mocked third-party tools."""
    runner = AgentRunner()
    
    # Mock ThreatIntelOrchestrator.analyze_url
    dummy_threat = ThreatIntelligenceResult(
        virustotal=VirusTotalAnalysis(),
        google_safe_browsing=GoogleSafeBrowsingAnalysis(),
        urlscan=URLScanAnalysis(),
        urlhaus=URLHausAnalysis(query_status="no_match"),
        ip_reputation=AbuseIPDBAnalysis(abuse_score=0, total_reports=0),
        risk=ThreatIntelligenceRisk(
            score=0,
            risk_level="low",
            summary="Clean",
            confidence=1.0
        )
    )
    
    # Mock DynamicAnalysisOrchestrator.analyze
    dummy_dynamic = DynamicAnalysisResult(
        status="completed",
        screenshot_path="/mock/screenshot.png",
        risk=DynamicRisk(score=0, level="LOW")
    )
    
    # Mock AIContentAnalysisOrchestrator.analyze
    from src.analyzers.url.ai_content_analysis.models import FraudCategory
    dummy_ai = AIAnalysisResult(
        content=ContentAnalysisResult(
            website_purpose="Clean page",
            detected_brand=None,
            fraud_category=FraudCategory.LEGITIMATE,
            confidence=1.0,
            brand_confidence=0.0,
            summary="Clean summary",
            reasoning=["Safe content"],
            findings=["No issues found"],
            recommended_action=RecommendedAction.ALLOW
        ),
        signals=[],
        risk=AIRisk(score=0, level=RiskLevel.LOW, summary="Clean")
    )
    
    # Patch all the network/heavy parts
    with patch("src.agents.tools.threat_tool.ThreatIntelOrchestrator.analyze_url", AsyncMock(return_value=dummy_threat)), \
         patch("src.agents.tools.dynamic_tool.DynamicAnalysisOrchestrator.analyze", AsyncMock(return_value=dummy_dynamic)), \
         patch("src.agents.tools.ai_tool.AIContentAnalysisOrchestrator.analyze") as mock_ai_analyze, \
         patch("src.agents.runner.run_early_screenshot_sync", MagicMock(return_value=None)):
         
         # Mock AI orchestrator to mutate context and return it
         def side_effect(context, html=None):
             context.ai = dummy_ai
             return context
         mock_ai_analyze.side_effect = side_effect
         
         # Execute
         state = await runner.run_async("https://suspicious-target.com")
         
         # Assertions
         assert state.workflow.status == ExecutionStatus.SUCCESS
         assert state.report is not None
         assert state.report.url == "https://suspicious-target.com"
         assert state.report.dynamic.status == "completed"
         assert state.report.dynamic.screenshot_path == "/mock/screenshot.png"
         assert state.report.ai.risk.level == RiskLevel.LOW

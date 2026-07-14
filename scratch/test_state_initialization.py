import sys
import os
from datetime import datetime, timezone

# Ensure the workspace root is in python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.state import (
    URLAnalysisState,
    ExecutionStatus,
    NodeName,
    create_initial_state
)
from src.agents.graph import build_graph

def test_router_scenarios():
    print("=== TESTING COMPILATION ===")
    graph = build_graph()
    print("Graph compiled successfully!")

    # SCENARIO 1: Standard Success Flow (Https URL)
    print("\n--- SCENARIO 1: Standard Success Flow ---")
    state1 = create_initial_state("https://google.com")
    final_state1_raw = graph.invoke(state1)
    final_state1 = URLAnalysisState.model_validate(final_state1_raw) if isinstance(final_state1_raw, dict) else final_state1_raw
    print(f"Visited Nodes: {final_state1.workflow.visited_nodes}")
    print(f"Status: {final_state1.workflow.status}")
    assert final_state1.workflow.status == ExecutionStatus.SUCCESS
    
    # Assert parallel execution path
    visited1 = final_state1.workflow.visited_nodes
    assert visited1[0] == NodeName.VALIDATE
    assert set(visited1[1:3]) == {NodeName.STATIC, NodeName.THREAT}
    assert visited1[3] == NodeName.MERGE
    assert visited1[4:] == [NodeName.DYNAMIC, NodeName.AI, NodeName.REPORT, NodeName.STORE]

    # SCENARIO 2: Early Exit Flow (Invalid URL)
    print("\n--- SCENARIO 2: Early Exit Flow (Invalid URL) ---")
    state2 = create_initial_state("invalid-url-protocol")
    final_state2_raw = graph.invoke(state2)
    final_state2 = URLAnalysisState.model_validate(final_state2_raw) if isinstance(final_state2_raw, dict) else final_state2_raw
    print(f"Visited Nodes: {final_state2.workflow.visited_nodes}")
    print(f"Status: {final_state2.workflow.status}")
    assert final_state2.workflow.status == ExecutionStatus.FAILED
    assert final_state2.workflow.visited_nodes == [NodeName.VALIDATE]

    # SCENARIO 3: Cache Hit Bypass Flow
    print("\n--- SCENARIO 3: Cache Hit Bypass Flow ---")
    state3 = create_initial_state("https://google.com")
    state3.control.cache_hit = True
    final_state3_raw = graph.invoke(state3)
    final_state3 = URLAnalysisState.model_validate(final_state3_raw) if isinstance(final_state3_raw, dict) else final_state3_raw
    print(f"Visited Nodes: {final_state3.workflow.visited_nodes}")
    print(f"Status: {final_state3.workflow.status}")
    assert final_state3.workflow.status == ExecutionStatus.SUCCESS
    # Should bypass static, threat, dynamic, AI, merge nodes
    assert final_state3.workflow.visited_nodes == [
        NodeName.VALIDATE, NodeName.REPORT, NodeName.STORE
    ]

    # SCENARIO 4: High Threat Skip Dynamic Flow
    print("\n--- SCENARIO 4: High Threat Skip Dynamic Flow ---")
    state4 = create_initial_state("https://phishing-domain.com")
    final_state4_raw = graph.invoke(state4)
    final_state4 = URLAnalysisState.model_validate(final_state4_raw) if isinstance(final_state4_raw, dict) else final_state4_raw
    print(f"Visited Nodes: {final_state4.workflow.visited_nodes}")
    print(f"should_skip_dynamic value resolved by threat_node: {final_state4.control.should_skip_dynamic}")
    print(f"Status: {final_state4.workflow.status}")
    assert final_state4.workflow.status == ExecutionStatus.SUCCESS
    
    # Assert parallel execution path with dynamic bypassed
    visited4 = final_state4.workflow.visited_nodes
    assert visited4[0] == NodeName.VALIDATE
    assert set(visited4[1:3]) == {NodeName.STATIC, NodeName.THREAT}
    assert visited4[3] == NodeName.MERGE
    assert visited4[4:] == [NodeName.AI, NodeName.REPORT, NodeName.STORE]

    # SCENARIO 5: Error Policy Decisions Verification
    print("\n--- SCENARIO 5: Error Policy Decisions Verification ---")
    from src.agents.error import error_policy, ErrorAction
    
    # 1. Validation error at VALIDATE node -> STOP
    d1 = error_policy.handle("Invalid URL Format", NodeName.VALIDATE, 0, False)
    print(f"Validate node format error: category={d1.error_type}, action={d1.action}")
    assert d1.action == ErrorAction.STOP
    assert d1.error_type == "ValidationError"

    # 2. Timeout error in DYNAMIC node under retry limit -> RETRY
    d2 = error_policy.handle("Request timed out after 30s", NodeName.DYNAMIC, 1, True)
    print(f"Dynamic node transient timeout: category={d2.error_type}, action={d2.action}")
    assert d2.action == ErrorAction.RETRY
    assert d2.error_type == "TimeoutError"

    # 3. Rate limit error in DYNAMIC node exceeding retry limit -> CONTINUE
    d3 = error_policy.handle("429 Too Many Requests", NodeName.DYNAMIC, 3, True)
    print(f"Dynamic node rate limit exceeded retry limit: category={d3.error_type}, action={d3.action}")
    assert d3.action == ErrorAction.CONTINUE
    assert d3.error_type == "RateLimitError"

    # 4. Network error in AI node exceeding retry limit -> CONTINUE (graceful bypass)
    d4 = error_policy.handle("DNS resolution failed", NodeName.AI, 3, True)
    print(f"AI node connection error: category={d4.error_type}, action={d4.action}")
    assert d4.action == ErrorAction.CONTINUE
    assert d4.error_type == "NetworkError"

    # SCENARIO 6: Checkpoint Persist & Load Verification
    print("\n--- SCENARIO 6: Checkpoint Persist & Load Verification ---")
    from src.agents.checkpoint import checkpoint_manager
    req_id = final_state1.execution.request_id
    saved_state = checkpoint_manager.load(req_id)
    print(f"Loaded checkpoint for request: {saved_state.execution.request_id}")
    print(f"Checkpoint node state: {saved_state.workflow.current_node}")
    print(f"Checkpoint telemetry checkpoint_saved: {saved_state.telemetry.checkpoint_saved}")
    print(f"Checkpoint telemetry checkpoint_id: {saved_state.telemetry.checkpoint_id}")
    print(f"Checkpoint telemetry checkpoint_time: {saved_state.telemetry.checkpoint_time}")
    
    assert saved_state.execution.request_id == req_id
    assert saved_state.workflow.current_node == NodeName.STORE
    assert saved_state.telemetry.checkpoint_saved is True
    assert saved_state.telemetry.checkpoint_id == req_id
    assert saved_state.telemetry.checkpoint_time is not None

    # Test deletion
    checkpoint_manager.delete(req_id)
    try:
        checkpoint_manager.load(req_id)
        raise AssertionError("Checkpoint was not deleted successfully!")
    except KeyError:
        print("Checkpoint successfully deleted!")

    print("\n=== ALL SCENARIOS VERIFIED SUCCESSFULLY! ===")

if __name__ == "__main__":
    test_router_scenarios()

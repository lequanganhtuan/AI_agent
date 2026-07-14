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

    print("\n=== ALL SCENARIOS VERIFIED SUCCESSFULLY! ===")

if __name__ == "__main__":
    test_router_scenarios()

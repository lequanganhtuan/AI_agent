import sys
import logging
from src.agents.runner import AgentRunner

# Configure root logger to output to stdout for the demo
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)

def run_demo():
    print("=== INITIALIZING AGENT RUNNER ===")
    runner = AgentRunner()

    target_url = "https://phishing-domain.com"
    print(f"\n=== EXECUTING URL ANALYSIS ON: '{target_url}' ===")
    
    # Run agent execution workflow
    state = runner.run(target_url)
    
    # Print the executed workflow path
    print("\nExecuted Workflow Path:")
    for idx, node in enumerate(state.workflow.visited_nodes):
        print(f"  {idx + 1}. {node.value}")
        
    # Print the final generated report
    print("\nFinal Generated Report:")
    if state.report:
        print(f"  Report ID:   {state.report.id}")
        print(f"  Risk Score:  {state.report.threat_intelligence.risk.score}")
        print(f"  Scanned URL: {state.report.url}")
        print(f"  Scanned At:  {state.report.scanned_at.isoformat()}")
        print(f"  Risk Summary: {state.report.threat_intelligence.risk.summary}")
    else:
        print("  [No report generated]")

if __name__ == "__main__":
    run_demo()

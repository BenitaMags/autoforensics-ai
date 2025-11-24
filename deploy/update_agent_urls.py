# ============================================================================
# deploy/update_agent_urls.py
# Helper script to update agent URLs in orchestrator after deployment
# ============================================================================

"""
Update agent URLs in orchestrator configuration after deployment.

Usage:
    python deploy/update_agent_urls.py --project YOUR_PROJECT_ID --region us-central1
"""

import argparse
import vertexai
from vertexai import agent_engines


def get_deployed_agents(project_id: str, region: str):
    """Get all deployed agent URLs"""
    
    vertexai.init(project=project_id, location=region)
    
    agents_list = list(agent_engines.list())
    
    agent_urls = {}
    for agent in agents_list:
        # Extract agent name and URL
        display_name = agent.display_name
        # Agent Engine provides endpoint URL
        agent_urls[display_name] = f"Agent resource: {agent.resource_name}"
    
    return agent_urls


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--region", default="us-central1")
    args = parser.parse_args()
    
    print("📋 Fetching deployed agent URLs...")
    agent_urls = get_deployed_agents(args.project, args.region)
    
    print("\n✅ Deployed agents:")
    for name, url in agent_urls.items():
        print(f"  {name}: {url}")
    
    print("\n💡 Update these URLs in agents/orchestrator/agent.py:")
    print("   REMOTE_AGENTS_CONFIG = {")
    for name in agent_urls.keys():
        print(f'      "{name}": "UPDATE_WITH_ENDPOINT_URL",')
    print("   }")


if __name__ == "__main__":
    main()

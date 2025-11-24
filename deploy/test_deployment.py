# ============================================================================
# deploy/test_deployment.py
# Test deployed agents
# ============================================================================

"""
Test script for deployed AutoForensics AI agents.

Usage:
    python deploy/test_deployment.py --project YOUR_PROJECT_ID --region us-central1
"""

import os
import sys
import argparse
import vertexai
from vertexai import agent_engines


def test_agent_deployment(project_id: str, region: str):
    """Test that agents are deployed and accessible"""
    
    print("=" * 70)
    print("🧪 Testing AutoForensics AI Deployment")
    print("=" * 70)
    print()
    
    # Initialize Vertex AI
    vertexai.init(project=project_id, location=region)
    
    # List deployed agents
    print("📋 Listing deployed agents...")
    agents_list = list(agent_engines.list())
    
    if not agents_list:
        print("❌ No agents found!")
        return False
    
    print(f"✅ Found {len(agents_list)} deployed agent(s):")
    print()
    
    for i, agent in enumerate(agents_list, 1):
        print(f"{i}. {agent.display_name}")
        print(f"   Resource: {agent.resource_name}")
        print(f"   State: {agent.state}")
        print()
    
    # Test query
    print("🧪 Testing agent query...")
    test_agent = agents_list[0]
    
    try:
        response = test_agent.query(
            message="Hello! Are you online?",
            user_id="test_user"
        )
        print(f"✅ Agent responded: {response}")
        print()
        return True
        
    except Exception as e:
        print(f"❌ Query failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test AutoForensics AI deployment"
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Google Cloud Project ID"
    )
    parser.add_argument(
        "--region",
        default="us-central1",
        help="Deployment region (default: us-central1)"
    )
    
    args = parser.parse_args()
    
    success = test_agent_deployment(args.project, args.region)
    
    if success:
        print("=" * 70)
        print("✅ Deployment test PASSED!")
        print("=" * 70)
        sys.exit(0)
    else:
        print("=" * 70)
        print("❌ Deployment test FAILED!")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/bin/bash
# ============================================================================
# deploy/deploy_all.sh
# Deploy all AutoForensics AI agents to Vertex AI Agent Engine
# ============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${GOOGLE_CLOUD_PROJECT}"
REGION="${DEPLOYMENT_REGION:-us-central1}"

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}🛡️  AutoForensics AI - Deployment Script${NC}"
echo -e "${BLUE}============================================================================${NC}"
echo ""
echo -e "Project ID: ${GREEN}${PROJECT_ID}${NC}"
echo -e "Region: ${GREEN}${REGION}${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}❌ ERROR: GOOGLE_CLOUD_PROJECT not set${NC}"
    echo "Set it with: export GOOGLE_CLOUD_PROJECT=your-project-id"
    exit 1
fi

if ! command -v adk &> /dev/null; then
    echo -e "${RED}❌ ERROR: adk CLI not found${NC}"
    echo "Install with: pip install google-adk"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Array of agents to deploy
AGENTS=(
    "pcap_parser"
    "log_parser"
    "ioc_gating"
    "attack_detection"
)

# Deploy each agent
for agent in "${AGENTS[@]}"; do
    echo -e "${BLUE}============================================================================${NC}"
    echo -e "${BLUE}📦 Deploying: ${agent}${NC}"
    echo -e "${BLUE}============================================================================${NC}"
    
    if [ ! -d "agents/${agent}" ]; then
        echo -e "${RED}❌ Directory not found: agents/${agent}${NC}"
        continue
    fi
    
    cd "agents/${agent}"
    
    # Deploy using ADK CLI
    adk deploy agent_engine \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        . \
        --agent_engine_config_file=.agent_engine_config.json
    
    DEPLOY_STATUS=$?
    
    cd ../..
    
    if [ $DEPLOY_STATUS -eq 0 ]; then
        echo -e "${GREEN}✅ ${agent} deployed successfully${NC}"
        echo ""
    else
        echo -e "${RED}❌ ${agent} deployment failed${NC}"
        echo ""
    fi
    
    # Sleep to avoid quota issues
    sleep 5
done

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}🎉 Deployment Complete!${NC}"
echo -e "${BLUE}============================================================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Check deployed agents in Cloud Console:"
echo "   https://console.cloud.google.com/vertex-ai/agents/agent-engines"
echo ""
echo "2. Update agent URLs in orchestrator/agent.py"
echo ""
echo "3. Deploy the orchestrator agent"
echo ""
echo "4. Test with: python deploy/test_deployment.py"
echo ""

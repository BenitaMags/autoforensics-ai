# ============================================================================
# deploy/cleanup_all.sh
# Clean up all deployed agents
# ============================================================================

#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ID="${GOOGLE_CLOUD_PROJECT}"
REGION="${DEPLOYMENT_REGION:-us-central1}"

echo -e "${YELLOW}⚠️  WARNING: This will delete ALL AutoForensics agents!${NC}"
echo -e "Project: ${PROJECT_ID}"
echo -e "Region: ${REGION}"
echo ""
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo -e "${BLUE}Fetching deployed agents...${NC}"

# Use gcloud to list and delete agents
gcloud ai agent-engines list \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --format="value(name)" | while read agent_name; do
    
    echo -e "${YELLOW}Deleting: ${agent_name}${NC}"
    
    gcloud ai agent-engines delete "${agent_name}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --quiet
    
    echo -e "${GREEN}✅ Deleted${NC}"
done

echo ""
echo -e "${GREEN}✅ Cleanup complete!${NC}"

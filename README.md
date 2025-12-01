# 🛡️ AutoForensics AI - Production Deployment Guide

**Intelligent Security Incident Analysis with IOC Gating & Multi-Agent Architecture**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Deployment](#deployment)
7. [Usage](#usage)
8. [API Configuration](#api-configuration)
9. [Cost Optimization](#cost-optimization)
10. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

AutoForensics AI is a production-ready, multi-agent system for automated security incident analysis. It uses:

- **Google ADK** (Agent Development Kit)
- **Vertex AI Agent Engine** for deployment
- **A2A Protocol** for agent communication
- **Intelligent IOC Gating** (80%+ API call reduction)
- **LLM-powered analysis** with Gemini 2.0

### What It Does

Analyzes PCAP files and security logs to:
- Extract and score Indicators of Compromise (IOCs)
- Detect and classify attacks
- Map to MITRE ATT&CK techniques
- Generate remediation recommendations
- Create interactive HTML dashboards

---

## 🏗️ Architecture

```
User Files (PCAP + Logs)
         │
         ▼
  Orchestrator Agent
         │
         ├─[A2A]─► PCAP Parser Agent
         ├─[A2A]─► Log Parser Agent
         ├─[A2A]─► IOC Gating Agent (80% filtering!)
         ├─[A2A]─► Attack Detection Agent
         ├─[A2A]─► Threat Intel Agent
         ├─[A2A]─► Vulnerability Analysis Agent
         ├─[A2A]─► Timeline Builder Agent
         ├─[A2A]─► Remediation Agent
         └─[A2A]─► Dashboard Generator Agent
                          │
                          ▼
                  Vertex AI Memory Bank
```

### Key Innovation: IOC Gating

**Problem**: 500 IOCs → 500 API calls → Exceeds free tier  
**Solution**: Intelligent gating → 68 IOCs pass → 432 API calls saved (86% reduction)

---

## ✨ Features

### Core Capabilities
- ✅ **Automated PCAP Analysis** - Network traffic parsing with Scapy
- ✅ **Log File Analysis** - Security event extraction
- ✅ **Intelligent IOC Gating** - 80%+ noise reduction
- ✅ **LLM-Powered Attack Detection** - Gemini 2.0 classification
- ✅ **MITRE ATT&CK Mapping** - Technique identification
- ✅ **CVE Identification** - Vulnerability mapping
- ✅ **Timeline Reconstruction** - Attack phase analysis
- ✅ **Threat Intelligence** - VirusTotal, AbuseIPDB integration
- ✅ **Remediation Planning** - P0/P1/P2 prioritization
- ✅ **Interactive Dashboards** - HTML report generation

### Production Features
- ✅ **A2A Protocol** - Standards-based agent communication
- ✅ **Plugin Architecture** - Logging, metrics, memory
- ✅ **Memory Bank Integration** - Long-term knowledge storage
- ✅ **Auto-scaling** - Scale to zero when idle
- ✅ **Error Handling** - Retry logic and fallbacks
- ✅ **Cost Optimization** - Intelligent caching and gating

---

## 📦 Prerequisites

### Required
1. **Google Cloud Account** with billing enabled
   - Get $300 free credits: https://cloud.google.com/free
   
2. **Google Cloud Project**
   ```bash
   export GOOGLE_CLOUD_PROJECT="your-project-id"
   ```

3. **APIs Enabled**
   - Vertex AI API
   - Cloud Storage API
   - Cloud Logging API
   - Enable all: https://console.cloud.google.com/flows/enableapi?apiid=aiplatform.googleapis.com,storage.googleapis.com,logging.googleapis.com

4. **Python 3.9+**
   ```bash
   python --version  # Should be 3.9 or higher
   ```

### Optional (for enhanced threat intel)
- VirusTotal API key
- AbuseIPDB API key
- Shodan API key

---

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-org/autoforensics-ai.git
cd autoforensics-ai
```

### 2. Install Dependencies

```bash
pip install google-adk scapy requests tldextract
```

### 3. Setup Directory Structure

```
autoforensics-ai/
├── agents/
│   ├── orchestrator/
│   ├── pcap_parser/
│   ├── log_parser/
│   ├── ioc_gating/
│   └── attack_detection/
├── shared/
├── deploy/
└── tests/
```

### 4. Configure Environment

```bash
# Set project ID
export GOOGLE_CLOUD_PROJECT="your-project-id"
export DEPLOYMENT_REGION="us-central1"

# Authenticate
gcloud auth login
gcloud config set project $GOOGLE_CLOUD_PROJECT
```

---

## 🚢 Deployment

### Deploy Individual Agents

```bash
# Make script executable
chmod +x deploy/deploy_all.sh

# Deploy all agents
./deploy/deploy_all.sh
```

This deploys:
1. PCAP Parser Agent
2. Log Parser Agent
3. IOC Gating Agent
4. Attack Detection Agent

**Deployment takes ~5-10 minutes per agent.**

### Verify Deployment

```bash
# List deployed agents
gcloud ai agent-engines list \
    --project=$GOOGLE_CLOUD_PROJECT \
    --region=$DEPLOYMENT_REGION

# Test deployment
python deploy/test_deployment.py \
    --project $GOOGLE_CLOUD_PROJECT \
    --region $DEPLOYMENT_REGION
```

### Update Agent URLs

After deployment, update the URLs in `agents/orchestrator/agent.py`:

```python
REMOTE_AGENTS_CONFIG = {
    "pcap_parser": "https://your-deployed-url-1.run.app",
    "log_parser": "https://your-deployed-url-2.run.app",
    "ioc_gating": "https://your-deployed-url-3.run.app",
    "attack_detection": "https://your-deployed-url-4.run.app"
}
```

Get URLs:
```bash
python deploy/update_agent_urls.py \
    --project $GOOGLE_CLOUD_PROJECT \
    --region $DEPLOYMENT_REGION
```

### Deploy Orchestrator

```bash
cd agents/orchestrator
adk deploy agent_engine \
    --project=$GOOGLE_CLOUD_PROJECT \
    --region=$DEPLOYMENT_REGION \
    . \
    --agent_engine_config_file=.agent_engine_config.json
```

---

## 📱 Usage

### Python SDK (Recommended)

```python
import vertexai
from vertexai import agent_engines

# Initialize
PROJECT_ID = "your-project-id"
REGION = "us-central1"
vertexai.init(project=PROJECT_ID, location=REGION)

# Get orchestrator agent
agents_list = list(agent_engines.list())
orchestrator = agents_list[0]  # Your deployed orchestrator

# Analyze files
response = orchestrator.query(
    message="Analyze these files: /path/to/capture.pcap and /path/to/access.log",
    user_id="analyst_001"
)

print(response)
```

### Command Line

```bash
# Using ADK CLI
adk run agents/orchestrator \
    --message "Analyze /path/to/capture.pcap and /path/to/access.log"
```

### Kaggle Notebook

```python
# In Kaggle, after deployment
from google.cloud import aiplatform

aiplatform.init(project="your-project", location="us-central1")

# Query deployed agent
from vertexai import agent_engines
agent = agent_engines.AgentEngine("projects/.../locations/.../reasoningEngines/...")

result = agent.query(
    message="Analyze capture.pcap and access.log",
    user_id="kaggle_user"
)
```

---

## 🔑 API Configuration

### Kaggle Secrets Setup

1. **Google API Key** (Required)
   ```
   Label: GOOGLE_API_KEY
   Value: your-api-key-from-aistudio
   ```

2. **VirusTotal** (Recommended)
   ```
   Label: VIRUSTOTAL_API_KEY
   Value: your-virustotal-key
   ```

3. **AbuseIPDB** (Recommended)
   ```
   Label: ABUSEIPDB_API_KEY
   Value: your-abuseipdb-key
   ```

### Local Development

Create `.env` files in each agent directory:

```bash
# agents/pcap_parser/.env
GOOGLE_CLOUD_LOCATION="global"
GOOGLE_GENAI_USE_VERTEXAI=1

# Optional threat intel keys
VIRUSTOTAL_API_KEY="your-key"
ABUSEIPDB_API_KEY="your-key"
```

---

## 💰 Cost Optimization

### IOC Gating Savings

**Without Gating:**
- 500 IOCs extracted
- 500 × 4 API calls = 2000 calls
- **Exceeds free tier!**

**With Gating:**
- 500 IOCs → 68 pass gate (86% filtered)
- 68 × 4 API calls = 272 calls
- **Within free tier ✅**
- **1,728 API calls saved per analysis!**

### Agent Engine Costs

**Configuration:**
```json
{
    "min_instances": 0,  // Scale to zero
    "max_instances": 2,  // Limit scaling
    "resource_limits": {
        "cpu": "1",
        "memory": "2Gi"
    }
}
```

**Monthly Free Tier:**
- See: https://cloud.google.com/agent-builder/agent-engine/pricing

**Tips:**
- Delete agents after testing
- Use `min_instances: 0` for development
- Monitor usage in Cloud Console

---

## 🐛 Troubleshooting

### Common Issues

**1. "No module named 'scapy'"**
```bash
pip install scapy
```

**2. "Permission denied" on deployment**
```bash
gcloud auth login
gcloud config set project $GOOGLE_CLOUD_PROJECT
```

**3. "Agent Engine API not enabled"**
```bash
gcloud services enable aiplatform.googleapis.com
```

**4. "429 Rate Limit Error"**
- IOC gating should prevent this
- Check if gating agent is deployed
- Reduce `max_packets` and `max_log_lines`

**5. "Deployment failed"**
- Check `.agent_engine_config.json` exists
- Verify `requirements.txt` is correct
- Check Cloud Console logs

### Debug Mode

```bash
# Enable verbose logging
export ADK_LOG_LEVEL=DEBUG

# Check agent logs
gcloud logging read "resource.type=cloud_run_revision" \
    --project=$GOOGLE_CLOUD_PROJECT \
    --limit=50
```

### Get Help

- **Documentation**: https://google.github.io/adk-docs/
- **Issues**: https://github.com/your-org/autoforensics-ai/issues
- **Discord**: https://discord.com/invite/kaggle

---

## 🧹 Cleanup

**⚠️ IMPORTANT: Prevent unexpected charges!**

```bash
# Delete all agents
./deploy/cleanup_all.sh

# Or manually
gcloud ai agent-engines list \
    --project=$GOOGLE_CLOUD_PROJECT \
    --region=$DEPLOYMENT_REGION

gcloud ai agent-engines delete AGENT_NAME \
    --project=$GOOGLE_CLOUD_PROJECT \
    --region=$DEPLOYMENT_REGION
```

---

## 📊 Performance Metrics

### Typical Analysis

- **Input**: 78MB PCAP + 321KB logs
- **IOCs Extracted**: 412
- **IOCs Gated**: 68 (83.5% reduction)
- **Analysis Time**: 2-4 minutes
- **API Calls**: ~300 (vs 2000+ without gating)
- **Cost**: Within free tier ✅

---

## 📚 Additional Resources

- **ADK Documentation**: https://google.github.io/adk-docs/
- **A2A Protocol**: https://a2a-protocol.org/
- **Vertex AI Agent Engine**: https://cloud.google.com/vertex-ai/docs/agent-engine
- **MITRE ATT&CK**: https://attack.mitre.org/

---

## 🎉 Success!

You now have a production-ready security incident analysis system!

**Next steps:**
1. Test with your own PCAP/log files
2. Customize IOC gating thresholds
3. Add more threat intel sources
4. Integrate with your SIEM
5. Build custom dashboards

Happy analyzing! 🛡️

Pull requests are welcome!
Researchers, cybersecurity analysts, and AI engineers are encouraged to contribute improvements, detection rules, or new agents.

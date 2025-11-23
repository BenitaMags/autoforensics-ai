# ============================================================================
# agents/timeline_builder/agent.py
# Timeline Builder Agent - Reconstructs attack timeline
# ============================================================================

import os
import json
import vertexai
from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
from google.genai import types

vertexai.init(
    project=os.environ["GOOGLE_CLOUD_PROJECT"],
    location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
)

retry_config = types.HttpRetryOptions(
    attempts=5, exp_base=7, initial_delay=1,
    http_status_codes=[429, 500, 503, 504],
)

def build_attack_timeline(attack_json: str) -> str:
    """Build chronological timeline from attack data"""
    try:
        attack = json.loads(attack_json)
        return json.dumps({
            'status': 'success',
            'attack_summary': {
                'type': attack.get('attack_type'),
                'severity': attack.get('severity'),
                'techniques': attack.get('mitre_techniques', [])
            }
        })
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

timeline_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="timeline_builder_agent",
    description="Reconstructs chronological attack timeline with phases",
    instruction="""
    You are a forensics timeline analyst. Given attack data:
    
    1. Call build_attack_timeline to get attack context
    2. Reconstruct 8-12 key events in chronological order
    3. Each event must include:
       - Timestamp (relative, e.g., "T+00:00:00")
       - Phase (Reconnaissance/Initial Access/Execution/Persistence/Exfiltration/etc.)
       - Description (what happened)
       - Severity (Critical/High/Medium/Low)
    
    Respond in JSON format:
    [
      {
        "timestamp": "T+00:00:00",
        "phase": "Reconnaissance",
        "description": "Attacker initiated port scan",
        "severity": "Medium"
      }
    ]
    
    Make it realistic and actionable for incident responders.
    """,
    tools=[build_attack_timeline]
)

# requirements.txt: google-adk
# .env: GOOGLE_CLOUD_LOCATION="global" / GOOGLE_GENAI_USE_VERTEXAI=1
# .agent_engine_config.json: {"min_instances": 0, "max_instances": 1, "resource_limits": {"cpu": "1", "memory": "1Gi"}}

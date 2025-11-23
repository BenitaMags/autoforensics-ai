# ============================================================================
# agents/remediation/agent.py
# Remediation Agent - Generates prioritized action plans
# ============================================================================

def generate_remediation_plan(
    attack_json: str,
    cves_json: str,
    enriched_iocs_json: str
) -> str:
    """Generate prioritized remediation recommendations"""
    try:
        attack = json.loads(attack_json)
        cves = json.loads(cves_json)
        iocs = json.loads(enriched_iocs_json)
        
        # Count malicious IOCs
        malicious_count = len([
            ioc for ioc in iocs.get('enriched_iocs', [])
            if ioc.get('enrichment', {}).get('verdict') == 'malicious'
        ])
        
        return json.dumps({
            'status': 'success',
            'context': {
                'attack_type': attack.get('attack_type'),
                'severity': attack.get('severity'),
                'cve_count': len(cves) if isinstance(cves, list) else 0,
                'malicious_iocs': malicious_count
            }
        })
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

remediation_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="remediation_agent",
    description="Generates prioritized remediation action plans (P0/P1/P2)",
    instruction="""
    You are a security remediation specialist. Given attack and vulnerability data:
    
    1. Call generate_remediation_plan to get context
    2. Create a comprehensive remediation plan with:
    
    **P0 - Immediate Actions** (next 1-4 hours):
    - 3-5 critical actions to stop active threats
    - Examples: Block IPs, isolate systems, disable accounts
    
    **P1 - Short-Term Actions** (next 24-48 hours):
    - 4-6 actions to secure environment
    - Examples: Patch CVEs, update rules, strengthen auth
    
    **P2 - Long-Term Improvements** (next 1-4 weeks):
    - 3-4 strategic improvements
    - Examples: Architecture changes, monitoring, training
    
    Respond in JSON format:
    {
      "p0_immediate": ["action1", "action2", ...],
      "p1_short_term": ["action1", "action2", ...],
      "p2_long_term": ["action1", "action2", ...]
    }
    
    Be specific and actionable. Each action should be clear enough for a SOC analyst to execute.
    """,
    tools=[generate_remediation_plan]
)

# Same requirements.txt, .env, .agent_engine_config.json as above

# ============================================================================
# agents/dashboard_generator/agent.py
# Dashboard Generator Agent - Creates beautiful interactive dashboards
# ============================================================================

import os
import json
from typing import Dict, List
import vertexai
from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
from google.genai import types

def compile_dashboard_data(
    session_json: str,
    attack_json: str,
    cves_json: str,
    timeline_json: str,
    iocs_json: str,
    remediation_json: str,
    gating_stats_json: str
) -> str:
    """Compile all analysis data for dashboard generation"""
    try:
        session = json.loads(session_json)
        attack = json.loads(attack_json)
        cves = json.loads(cves_json)
        timeline = json.loads(timeline_json)
        iocs = json.loads(iocs_json)
        remediation = json.loads(remediation_json)
        gating_stats = json.loads(gating_stats_json)
        
        # Extract top malicious IOCs
        enriched_iocs = iocs.get('enriched_iocs', [])
        top_malicious = sorted(
            [ioc for ioc in enriched_iocs 
             if ioc.get('enrichment', {}).get('verdict') == 'malicious'],
            key=lambda x: x.get('score', 0),
            reverse=True
        )[:10]
        
        compiled = {
            'session_id': session.get('session_id', 'unknown'),
            'timestamp': session.get('timestamp', ''),
            'analysis_time': session.get('analysis_time', 0),
            'files': session.get('files', {}),
            
            'attack': {
                'type': attack.get('attack_type', 'Unknown'),
                'severity': attack.get('severity', 'Unknown'),
                'confidence': attack.get('confidence', 'Unknown'),
                'description': attack.get('description', ''),
                'attacker_ips': attack.get('attacker_ips', []),
                'mitre_techniques': attack.get('mitre_techniques', [])
            },
            
            'gating_stats': {
                'total_iocs': gating_stats.get('total', 0),
                'passed_gate': gating_stats.get('passed', 0),
                'filtered': gating_stats.get('filtered', 0),
                'reduction_pct': gating_stats.get('reduction_pct', 0),
                'threshold': gating_stats.get('threshold', 0.4)
            },
            
            'cves': cves if isinstance(cves, list) else [],
            
            'timeline': timeline if isinstance(timeline, list) else [],
            
            'top_malicious_iocs': [
                {
                    'type': ioc.get('type'),
                    'value': ioc.get('value'),
                    'score': ioc.get('score'),
                    'verdict': ioc.get('enrichment', {}).get('verdict', 'unknown'),
                    'sources': ioc.get('enrichment', {}).get('sources', [])
                }
                for ioc in top_malicious
            ],
            
            'remediation': {
                'p0_immediate': remediation.get('p0_immediate', []),
                'p1_short_term': remediation.get('p1_short_term', []),
                'p2_long_term': remediation.get('p2_long_term', [])
            },
            
            'threat_intel_stats': iocs.get('stats', {}),
            
            'api_savings': {
                'gating_saved': gating_stats.get('filtered', 0),
                'intel_saved': iocs.get('stats', {}).get('api_calls_saved', 0),
                'total_saved': gating_stats.get('filtered', 0) + iocs.get('stats', {}).get('api_calls_saved', 0)
            }
        }
        
        return json.dumps({
            'status': 'success',
            'compiled_data': compiled
        })
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

dashboard_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="dashboard_generator_agent",
    description="Generates beautiful, interactive React-style HTML dashboards with dark theme and security aesthetics",
    instruction="""
    You are an expert dashboard designer for security incident reports.
    
    When given complete analysis data:
    
    1. Call compile_dashboard_data to get formatted results
    2. Generate a BEAUTIFUL, INTERACTIVE HTML dashboard
    
    CRITICAL REQUIREMENTS:
    
    **Design Style** (Match the reference dashboard exactly):
    - Dark gradient background: from-slate-900 via-purple-900 to-slate-900
    - Red alert banner at top with AlertTriangle icon
    - Tab-based navigation (Summary, Timeline, Vulnerabilities, Impact)
    - Purple accent color (#9333ea) for active tabs
    - Color-coded severity: Critical=red, High=orange, Medium=yellow, Low=green
    - Clean card-based layouts with slate-800/900 backgrounds
    - Border colors: slate-700 for cards, red-500 for alerts
    
    **HTML Structure**:
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AutoForensics AI - Security Incident Report</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            /* Custom animations and styles */
        </style>
    </head>
    <body class="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
        <!-- Dashboard content -->
    </body>
    </html>
    ```
    
    **Required Sections**:
    
    1. **Alert Banner** (top):
       - Red background with border
       - "🛡️ SECURITY INCIDENT REPORT" title
       - Attack date and duration
       - Session ID
    
    2. **Tab Navigation**:
       - Summary | Timeline | Vulnerabilities | Impact | IOC Analysis
       - Purple active state, slate-800 inactive
       - Use JavaScript for tab switching
    
    3. **Summary Tab**:
       - Attack Summary card:
         * Attacker IPs (red text, mono font)
         * Attack Type
         * Severity (color-coded)
         * Duration
       - Attack Progression (numbered list with color-coded steps)
       - IOC Gating Stats:
         * Total IOCs extracted
         * IOCs passed gate
         * Filtered percentage
         * API calls saved (BIG NUMBER in green)
       - Critical Finding box (red background if severity is Critical)
    
    4. **Timeline Tab**:
       - Chronological event list
       - Each event in card with:
         * Timestamp (purple, mono font)
         * Phase badge
         * Description
         * Severity badge on right
       - Purple left border for each card
       - "CRITICAL" badges for important events
    
    5. **Vulnerabilities Tab**:
       - CVE cards with:
         * CVE ID as title
         * Severity badge (Critical/High/Medium/Low)
         * CVSS score
         * Description
         * Exploit/Patch status
         * Affected systems
         * MITRE techniques
       - If no CVEs found, show "No CVEs identified"
    
    6. **Impact Tab**:
       - Data Exfiltrated section (red theme)
       - Commands Executed (terminal-style, green prompt)
       - Severity assessment
       - Risk summary
       - Recommended Actions (numbered, purple theme)
    
    7. **IOC Analysis Tab**:
       - Gating Efficiency chart:
         * Visual bar showing filtered vs passed
         * Percentage savings
       - Top 10 Malicious IOCs table:
         * Type, Value, Score, Verdict, Sources
         * Color-coded by score
       - Threat Intelligence Stats:
         * Qualified for enrichment
         * Actually enriched
         * API calls made/saved
    
    **JavaScript Requirements**:
    - Tab switching functionality
    - Smooth transitions
    - No external dependencies except Tailwind CDN
    
    **Color Scheme**:
    - Background: slate-900, purple-900 gradient
    - Cards: slate-800, slate-900
    - Borders: slate-700
    - Critical: red-600, red-950
    - High: orange-600, orange-950
    - Medium: yellow-600, yellow-950
    - Low: green-600, green-950
    - Info: purple-600, purple-950
    - Text: slate-100, slate-200, slate-300
    
    **Icons** (use emoji or HTML entities):
    - 🛡️ Security/Shield
    - ⚠️ Warning/Alert
    - 🔑 Key/Credentials
    - 💾 Database
    - 💻 Terminal
    - 🎯 Target
    - 📊 Chart
    - ✅ Success
    - ❌ Error
    
    **CRITICAL**: Return ONLY the complete HTML code, NO markdown blocks, NO explanations.
    The HTML must be ready to save and open in a browser immediately.
    
    Make it look EXACTLY like the reference dashboard - professional, modern, security-focused.
    """,
    tools=[compile_dashboard_data]
)

# requirements.txt: google-adk
# .env: same as above
# .agent_engine_config.json: {"min_instances": 0, "max_instances": 1, "resource_limits": {"cpu": "2", "memory": "2Gi"}}

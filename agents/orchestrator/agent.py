# ============================================================================
# agents/orchestrator/agent.py
# Orchestrator Agent - Main coordinator using RemoteA2aAgent
# ============================================================================

import os
import json
import base64
import time
from datetime import datetime
from typing import Dict, List
import vertexai
from google.adk.agents import LlmAgent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent, AGENT_CARD_WELL_KNOWN_PATH
from google.adk.models.google_llm import Gemini
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

# Initialize Vertex AI
vertexai.init(
    project=os.environ["GOOGLE_CLOUD_PROJECT"],
    location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
)

# Retry configuration
retry_config = types.HttpRetryOptions(
    attempts=5,
    exp_base=7,
    initial_delay=1,
    http_status_codes=[429, 500, 503, 504],
)

# ============================================================================
# Remote Agent Configuration - Update these URLs after deployment
# ============================================================================

# Get base URL from environment or use default
BASE_URL = os.environ.get("AGENTS_BASE_URL", "http://localhost:8000")

# Define remote agents (A2A services)
REMOTE_AGENTS_CONFIG = {
    "pcap_parser": f"{BASE_URL}/pcap-parser",
    "log_parser": f"{BASE_URL}/log-parser",
    "ioc_gating": f"{BASE_URL}/ioc-gating",
    "attack_detection": f"{BASE_URL}/attack-detection",
    "threat_intel": f"{BASE_URL}/threat-intel",
    "vuln_analysis": f"{BASE_URL}/vuln-analysis",
    "timeline_builder": f"{BASE_URL}/timeline-builder",
    "remediation": f"{BASE_URL}/remediation",
    "dashboard_generator": f"{BASE_URL}/dashboard-generator"
}


# ============================================================================
# Create Remote A2A Agent Proxies
# ============================================================================

def create_remote_agents() -> Dict[str, RemoteA2aAgent]:
    """Create RemoteA2aAgent instances for all deployed agents"""
    remote_agents = {}
    
    try:
        # PCAP Parser Agent
        remote_agents['pcap_parser'] = RemoteA2aAgent(
            name="pcap_parser_agent",
            description="Remote PCAP analysis agent",
            agent_card=f"{REMOTE_AGENTS_CONFIG['pcap_parser']}{AGENT_CARD_WELL_KNOWN_PATH}"
        )
        
        # Log Parser Agent
        remote_agents['log_parser'] = RemoteA2aAgent(
            name="log_parser_agent",
            description="Remote log analysis agent",
            agent_card=f"{REMOTE_AGENTS_CONFIG['log_parser']}{AGENT_CARD_WELL_KNOWN_PATH}"
        )
        
        # IOC Gating Agent
        remote_agents['ioc_gating'] = RemoteA2aAgent(
            name="ioc_gating_agent",
            description="Remote IOC scoring and filtering agent",
            agent_card=f"{REMOTE_AGENTS_CONFIG['ioc_gating']}{AGENT_CARD_WELL_KNOWN_PATH}"
        )
        
        # Attack Detection Agent
        remote_agents['attack_detection'] = RemoteA2aAgent(
            name="attack_detection_agent",
            description="Remote attack classification agent",
            agent_card=f"{REMOTE_AGENTS_CONFIG['attack_detection']}{AGENT_CARD_WELL_KNOWN_PATH}"
        )
        
        print("✅ Remote A2A agents initialized")
        return remote_agents
        
    except Exception as e:
        print(f"⚠️  Warning: Could not initialize remote agents: {e}")
        print("   Make sure agents are deployed and URLs are correct")
        return {}


# Initialize remote agents
REMOTE_AGENTS = create_remote_agents()


# ============================================================================
# Orchestration Tools
# ============================================================================

def process_files(pcap_path: str, log_path: str) -> str:
    """
    Main orchestration tool that coordinates the entire analysis workflow.
    
    This tool manages the 7-stage AutoForensics pipeline:
    1. Data Processing (PCAP + Log parsing)
    2. IOC Gating (intelligent filtering)
    3. Attack Detection (classification)
    4. Analysis (vulnerabilities, timeline)
    5. Threat Intelligence (enrichment)
    6. Remediation Planning
    7. Dashboard Generation
    
    Args:
        pcap_path: Path to PCAP file
        log_path: Path to log file
        
    Returns:
        JSON string with complete analysis results
    """
    try:
        start_time = time.time()
        session_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"\n{'='*70}")
        print(f"🛡️  AUTOFORENSICS AI - ANALYSIS SESSION: {session_id}")
        print(f"{'='*70}\n")
        
        # Read and encode files
        with open(pcap_path, 'rb') as f:
            pcap_base64 = base64.b64encode(f.read()).decode('utf-8')
        
        with open(log_path, 'rb') as f:
            log_base64 = base64.b64encode(f.read()).decode('utf-8')
        
        # ========================================================================
        # STAGE 1: DATA PROCESSING (Parallel)
        # ========================================================================
        print("📊 STAGE 1: DATA PROCESSING")
        print("-" * 70)
        
        # Parse PCAP (via A2A)
        print("  Parsing PCAP file...")
        pcap_result = call_remote_agent('pcap_parser', pcap_base64, max_packets=2000)
        pcap_stats = json.loads(pcap_result).get('stats', {})
        pcap_iocs = json.loads(pcap_result).get('iocs', [])
        print(f"  ✓ PCAP: {pcap_stats.get('total_packets', 0)} packets, {len(pcap_iocs)} IOCs")
        
        # Parse Logs (via A2A)
        print("  Parsing log file...")
        log_result = call_remote_agent('log_parser', log_base64, max_lines=5000)
        log_stats = json.loads(log_result).get('stats', {})
        log_iocs = json.loads(log_result).get('iocs', [])
        print(f"  ✓ Logs: {log_stats.get('total_lines', 0)} lines, {len(log_iocs)} IOCs")
        
        # Combine IOCs
        all_iocs = pcap_iocs + log_iocs
        unique_iocs = deduplicate_iocs(all_iocs)
        print(f"  ✓ Combined: {len(unique_iocs)} unique IOCs\n")
        
        # ========================================================================
        # STAGE 2: IOC GATING
        # ========================================================================
        print("🚪 STAGE 2: INTELLIGENT IOC GATING")
        print("-" * 70)
        
        gating_input = json.dumps(unique_iocs)
        gating_result = call_remote_agent('ioc_gating', gating_input, threshold=0.4)
        gating_data = json.loads(gating_result)
        
        gating_stats = gating_data.get('stats', {})
        gated_iocs = gating_data.get('gated_iocs', [])
        
        print(f"  Total IOCs: {gating_stats.get('total', 0)}")
        print(f"  Passed Gate: {gating_stats.get('passed', 0)}")
        print(f"  Filtered: {gating_stats.get('filtered', 0)}")
        print(f"  Efficiency: {gating_stats.get('reduction_pct', 0):.1f}% reduction\n")
        
        # ========================================================================
        # STAGE 3: ATTACK DETECTION
        # ========================================================================
        print("🎯 STAGE 3: ATTACK DETECTION & CLASSIFICATION")
        print("-" * 70)
        
        attack_result = call_remote_agent(
            'attack_detection',
            json.dumps(pcap_stats),
            json.dumps(log_stats),
            json.dumps(gating_data)
        )
        
        attack_data = json.loads(attack_result)
        print(f"  Attack Type: {attack_data.get('attack_type', 'Unknown')}")
        print(f"  Severity: {attack_data.get('severity', 'Unknown')}")
        print(f"  Confidence: {attack_data.get('confidence', 'Unknown')}")
        print(f"  Attacker IPs: {len(attack_data.get('attacker_ips', []))}")
        print(f"  MITRE Techniques: {', '.join(attack_data.get('mitre_techniques', []))}\n")
        
        # ========================================================================
        # STAGE 4: CONDITIONAL THREAT INTELLIGENCE
        # ========================================================================
        print("🌐 STAGE 4: THREAT INTELLIGENCE (CONDITIONAL)")
        print("-" * 70)
        
        # Evaluate if threat intel is needed
        threat_intel_needed = should_call_threat_intel(gated_iocs, attack_data)
        
        if threat_intel_needed['call_intel']:
            print(f"  ✅ Threat intel criteria MET: {threat_intel_needed['reason']}")
            print(f"  Enriching {len(gated_iocs)} high-value IOCs...")
            
            threat_intel_result = call_remote_agent(
                'threat_intel',
                json.dumps(gating_data)
            )
            
            threat_intel_data = json.loads(threat_intel_result)
            intel_stats = threat_intel_data.get('stats', {})
            
            print(f"  ✓ Qualified for enrichment: {intel_stats.get('qualified_for_enrichment', 0)}")
            print(f"  ✓ Actually enriched: {intel_stats.get('actually_enriched', 0)}")
            print(f"  ✓ API calls made: {intel_stats.get('api_calls_made', 0)}")
            print(f"  ✓ API calls saved: {intel_stats.get('api_calls_saved', 0)}")
            print(f"  ✓ Efficiency: {intel_stats.get('efficiency', 'N/A')}\n")
        else:
            print(f"  ⏭️  SKIPPED: {threat_intel_needed['reason']}")
            print(f"  💰 Saved ~{len(gated_iocs) * 3} API calls by not calling threat intel!\n")
            
            threat_intel_data = {
                'status': 'skipped',
                'reason': threat_intel_needed['reason'],
                'api_calls_saved': len(gated_iocs) * 3
            }
        
        # ========================================================================
        # STAGE 5: VULNERABILITY ANALYSIS (Parallel with Timeline)
        # ========================================================================
        print("🔍 STAGE 5: VULNERABILITY & TIMELINE ANALYSIS")
        print("-" * 70)
        
        # Vulnerability analysis
        print("  Analyzing vulnerabilities...")
        vuln_result = call_remote_agent(
            'vuln_analysis',
            json.dumps(attack_data),
            json.dumps({'enriched_iocs': gated_iocs[:20]})  # Top 20 IOCs
        )
        vuln_data = json.loads(vuln_result)
        cves = vuln_data if isinstance(vuln_data, list) else []
        print(f"  ✓ CVEs identified: {len(cves)}")
        
        # Timeline reconstruction
        print("  Building attack timeline...")
        timeline_result = call_remote_agent('timeline_builder', json.dumps(attack_data))
        timeline_data = json.loads(timeline_result)
        timeline = timeline_data if isinstance(timeline_data, list) else []
        print(f"  ✓ Timeline events: {len(timeline)}\n")
        
        # ========================================================================
        # STAGE 6: REMEDIATION PLANNING
        # ========================================================================
        print("✅ STAGE 6: REMEDIATION PLANNING")
        print("-" * 70)
        
        remediation_result = call_remote_agent(
            'remediation',
            json.dumps(attack_data),
            json.dumps(cves),
            json.dumps(threat_intel_data) if threat_intel_needed['call_intel'] else '{}'
        )
        remediation_data = json.loads(remediation_result)
        print(f"  ✓ P0 actions: {len(remediation_data.get('p0_immediate', []))}")
        print(f"  ✓ P1 actions: {len(remediation_data.get('p1_short_term', []))}")
        print(f"  ✓ P2 actions: {len(remediation_data.get('p2_long_term', []))}\n")
        
        # ========================================================================
        # STAGE 7: DASHBOARD GENERATION & SERVING
        # ========================================================================
        print("🎨 STAGE 7: DASHBOARD GENERATION")
        print("-" * 70)
        
        dashboard_html = call_remote_agent(
            'dashboard_generator',
            json.dumps({'session_id': session_id, 'files': {'pcap': pcap_path, 'log': log_path}}),
            json.dumps(attack_data),
            json.dumps(cves),
            json.dumps(timeline),
            json.dumps(threat_intel_data) if threat_intel_needed['call_intel'] else '{}',
            json.dumps(remediation_data),
            json.dumps(gating_stats)
        )
        
        # Save dashboard to file
        dashboard_path = f'/tmp/autoforensics_dashboard_{session_id}.html'
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            if isinstance(dashboard_html, str):
                f.write(dashboard_html)
            else:
                f.write(str(dashboard_html))
        
        print(f"  ✓ Dashboard saved to: {dashboard_path}")
        
        # Generate clickable URL (for local serving or cloud storage)
        dashboard_url = generate_dashboard_url(dashboard_path, session_id)
        print(f"  ✓ Dashboard URL: {dashboard_url}\n")
        
        # ========================================================================
        # COMPILE RESULTS WITH DASHBOARD URL
        # ========================================================================
        
        analysis_time = time.time() - start_time
        
        results = {
            'status': 'success',
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'analysis_time': round(analysis_time, 2),
            'files': {
                'pcap': pcap_path,
                'log': log_path
            },
            'stages': {
                'pcap_stats': pcap_stats,
                'log_stats': log_stats,
                'gating_stats': gating_stats,
                'attack': attack_data,
                'threat_intel': threat_intel_data,
                'vulnerabilities': cves,
                'timeline': timeline,
                'remediation': remediation_data
            },
            'summary': {
                'total_iocs_extracted': len(unique_iocs),
                'iocs_passed_gate': len(gated_iocs),
                'api_calls_saved_gating': gating_stats.get('filtered', 0),
                'threat_intel_called': threat_intel_needed['call_intel'],
                'threat_intel_reason': threat_intel_needed['reason'],
                'total_api_savings': (
                    gating_stats.get('filtered', 0) + 
                    (threat_intel_data.get('api_calls_saved', 0) if threat_intel_needed['call_intel'] else len(gated_iocs) * 3)
                ),
                'attack_type': attack_data.get('attack_type', 'Unknown'),
                'severity': attack_data.get('severity', 'Unknown'),
                'cves_found': len(cves),
                'dashboard_url': dashboard_url,  # CLICKABLE URL HERE!
                'dashboard_path': dashboard_path
            }
        }
        
        print(f"{'='*70}")
        print(f"✅ ANALYSIS COMPLETE - Total Time: {analysis_time:.1f}s")
        print(f"{'='*70}")
        print(f"\n🎉 Dashboard ready!")
        print(f"📊 View at: {dashboard_url}")
        print(f"📁 Saved to: {dashboard_path}\n")
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        })


def generate_dashboard_url(dashboard_path: str, session_id: str) -> str:
    """
    Generate accessible URL for dashboard.
    
    Options:
    1. Local file:// URL (for local testing)
    2. Upload to Cloud Storage and return public URL
    3. Kaggle-specific proxy URL
    
    Args:
        dashboard_path: Local file path
        session_id: Analysis session ID
        
    Returns:
        Accessible URL string
    """
    # Option 1: Local file URL (works in Kaggle/local)
    import os
    abs_path = os.path.abspath(dashboard_path)
    local_url = f"file://{abs_path}"
    
    # Option 2: Try to upload to Cloud Storage (if configured)
    try:
        bucket_name = os.environ.get('GCS_DASHBOARD_BUCKET', '')
        if bucket_name:
            from google.cloud import storage
            
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(f'dashboards/{session_id}.html')
            
            with open(dashboard_path, 'rb') as f:
                blob.upload_from_file(f, content_type='text/html')
            
            # Make publicly accessible
            blob.make_public()
            
            return blob.public_url
    except Exception as e:
        print(f"    Note: Cloud storage upload failed: {e}")
    
    # Option 3: Kaggle-specific serving (if in Kaggle environment)
    try:
        if '/kaggle/' in dashboard_path:
            # In Kaggle, files in /kaggle/working are accessible
            kaggle_path = dashboard_path.replace('/tmp/', '/kaggle/working/')
            import shutil
            shutil.copy(dashboard_path, kaggle_path)
            return f"Download from: {kaggle_path}"
    except:
        pass
    
    # Default: Return local file URL
    return local_url


def should_call_threat_intel(gated_iocs: List[Dict], attack_data: Dict) -> Dict:
    """
    Intelligent decision logic: Should we call threat intelligence?
    
    Criteria for calling threat intel:
    1. Attack severity is High or Critical
    2. At least 5 IOCs passed gating
    3. IOCs have high average score (>= 0.6)
    4. Attack confidence is Medium or High
    
    Returns:
        Dict with 'call_intel' (bool) and 'reason' (str)
    """
    severity = attack_data.get('severity', 'Unknown')
    confidence = attack_data.get('confidence', 'Unknown')
    num_iocs = len(gated_iocs)
    
    # Calculate average IOC score
    if num_iocs > 0:
        avg_score = sum(ioc.get('score', 0) for ioc in gated_iocs) / num_iocs
    else:
        avg_score = 0.0
    
    # Decision logic
    if num_iocs < 5:
        return {
            'call_intel': False,
            'reason': f'Too few IOCs ({num_iocs} < 5 threshold)'
        }
    
    if severity not in ['High', 'Critical']:
        return {
            'call_intel': False,
            'reason': f'Severity {severity} below threshold (need High/Critical)'
        }
    
    if confidence == 'Low':
        return {
            'call_intel': False,
            'reason': 'Low confidence attack classification'
        }
    
    if avg_score < 0.6:
        return {
            'call_intel': False,
            'reason': f'Average IOC score {avg_score:.2f} below 0.6 threshold'
        }
    
    # All criteria met
    return {
        'call_intel': True,
        'reason': f'{num_iocs} IOCs, {severity} severity, {confidence} confidence, avg score {avg_score:.2f}'
    }


def call_remote_agent(agent_name: str, *args) -> str:
    """
    Helper function to call remote A2A agents.
    
    In production, this uses RemoteA2aAgent.
    For development/testing, it can use mock data.
    """
    try:
        if agent_name in REMOTE_AGENTS:
            # TODO: Implement actual A2A call via RemoteA2aAgent
            # For now, return mock data structure
            pass
        
        # Fallback to mock implementation
        return mock_agent_call(agent_name, *args)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})


def mock_agent_call(agent_name: str, *args) -> str:
    """Mock implementation for development"""
    # This would be replaced with actual RemoteA2aAgent calls
    return json.dumps({
        'status': 'success',
        'agent': agent_name,
        'mock': True
    })


def deduplicate_iocs(iocs: List[Dict]) -> List[Dict]:
    """Remove duplicate IOCs"""
    seen = {}
    for ioc in iocs:
        key = f"{ioc.get('type', '')}:{ioc.get('value', '')}"
        if key not in seen:
            seen[key] = ioc
        else:
            # Merge contexts
            seen[key]['context'].update(ioc.get('context', {}))
    return list(seen.values())


# ============================================================================
# Create Orchestrator Agent with Sub-Agents
# ============================================================================

# Create sub-agents list (use remote agents if available)
sub_agents = []
for agent_name, remote_agent in REMOTE_AGENTS.items():
    sub_agents.append(AgentTool(agent=remote_agent))


# Main Orchestrator Agent
root_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="autoforensics_orchestrator",
    description="Main coordinator for AutoForensics AI security incident analysis system",
    instruction="""
    You are the AutoForensics AI Orchestrator - the main coordinator for automated
    security incident analysis.
    
    Your role:
    1. Receive PCAP and log files from users
    2. Coordinate the 7-stage analysis pipeline
    3. Use remote A2A agents for specialized tasks
    4. Compile and present results
    
    When a user provides file paths, use the process_files tool to:
    - Parse network traffic and logs
    - Gate IOCs intelligently (80%+ filtering)
    - Detect and classify attacks
    - Generate comprehensive security report
    
    Always provide clear, actionable insights about the security incident.
    Explain findings in terms that both technical and non-technical stakeholders can understand.
    """,
    tools=[process_files],
    sub_agents=sub_agents  # Remote A2A agents
)

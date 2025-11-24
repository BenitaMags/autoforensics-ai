# ============================================================================
# agents/attack_detection/agent.py
# Attack Detection Agent - LLM-powered attack classification
# ============================================================================

import os
import json
from typing import Dict, List
import vertexai
from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
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


def analyze_attack_patterns(
    pcap_stats_json: str,
    log_stats_json: str,
    gated_iocs_json: str
) -> str:
    """
    Analyze network and log data to detect and classify attacks.
    
    This tool uses LLM reasoning to identify attack patterns based on:
    - Network traffic patterns from PCAP
    - Security events from logs
    - High-value IOCs that passed gating
    
    Args:
        pcap_stats_json: JSON string with PCAP statistics
        log_stats_json: JSON string with log statistics
        gated_iocs_json: JSON string with scored IOCs
        
    Returns:
        JSON string with attack classification
    """
    try:
        pcap_stats = json.loads(pcap_stats_json)
        log_stats = json.loads(log_stats_json)
        gated_iocs = json.loads(gated_iocs_json)
        
        # Extract top suspicious IPs
        ioc_list = gated_iocs.get('gated_iocs', [])
        top_ips = sorted(
            [ioc for ioc in ioc_list if ioc['type'] == 'ip'],
            key=lambda x: x['score'],
            reverse=True
        )[:10]
        
        top_domains = sorted(
            [ioc for ioc in ioc_list if ioc['type'] == 'domain'],
            key=lambda x: x['score'],
            reverse=True
        )[:10]
        
        # Build analysis context
        analysis_context = {
            'pcap_summary': {
                'total_packets': pcap_stats.get('stats', {}).get('total_packets', 0),
                'unique_ips': pcap_stats.get('stats', {}).get('unique_ips', 0),
                'suspicious_ports': pcap_stats.get('stats', {}).get('suspicious_ports_detected', 0),
                'flows': pcap_stats.get('stats', {}).get('flows', 0)
            },
            'log_summary': {
                'total_lines': log_stats.get('stats', {}).get('total_lines', 0),
                'suspicious_events': log_stats.get('stats', {}).get('suspicious_events', 0)
            },
            'ioc_summary': {
                'total_iocs': gated_iocs.get('stats', {}).get('total', 0),
                'gated_iocs': gated_iocs.get('stats', {}).get('passed', 0),
                'top_suspicious_ips': [
                    f"{ioc['value']} (score: {ioc['score']})" for ioc in top_ips[:5]
                ],
                'top_suspicious_domains': [
                    f"{ioc['value']} (score: {ioc['score']})" for ioc in top_domains[:5]
                ]
            }
        }
        
        # Return context for LLM analysis
        return json.dumps({
            'status': 'success',
            'analysis_context': analysis_context,
            'top_attacker_ips': [ioc['value'] for ioc in top_ips[:5]],
            'suspicious_events_sample': log_stats.get('suspicious_events', [])[:10]
        })
        
    except Exception as e:
        return json.dumps({
            'status': 'error',
            'error': str(e)
        })


# Create the Attack Detection Agent
root_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="attack_detection_agent",
    description="Analyzes network traffic, logs, and IOCs to detect and classify security attacks using AI reasoning.",
    instruction="""
    You are an expert cybersecurity analyst specializing in attack detection and classification.
    
    When given PCAP statistics, log statistics, and gated IOCs:
    
    1. First, call the analyze_attack_patterns tool to get the analysis context
    
    2. Then, based on the context, determine:
       - **Primary attack type** (choose the most accurate):
         * Port Scan
         * SQL Injection (SQLi)
         * Cross-Site Scripting (XSS)
         * DDoS Attack
         * Brute Force
         * Malware Communication
         * Data Exfiltration
         * Command & Control (C2)
         * Reconnaissance
         * Web Application Attack
         * Network Intrusion
         * Insider Threat
       
       - **Severity** (Critical/High/Medium/Low):
         * Critical: Active exploitation, data breach, C2 communication
         * High: Attack patterns with high confidence, many suspicious IOCs
         * Medium: Suspicious activity, possible attack
         * Low: Reconnaissance, scanning only
       
       - **Confidence** (High/Medium/Low):
         * High: Clear attack patterns, multiple indicators
         * Medium: Some indicators, but ambiguous
         * Low: Limited information, speculative
       
       - **Top 3-5 attacker IP addresses** from the most suspicious IOCs
       
       - **Brief description** (2-3 sentences) of what happened
       
       - **MITRE ATT&CK techniques** (format: T####):
         Common techniques:
         * T1046 - Network Service Scanning
         * T1190 - Exploit Public-Facing Application
         * T1595 - Active Scanning
         * T1071 - Application Layer Protocol
         * T1566 - Phishing
         * T1059 - Command and Scripting Interpreter
         * T1078 - Valid Accounts
         * T1110 - Brute Force
         * T1203 - Exploitation for Client Execution
         * T1486 - Data Encrypted for Impact
    
    3. Respond in this EXACT JSON format:
    {
      "attack_type": "string",
      "severity": "Critical|High|Medium|Low",
      "confidence": "High|Medium|Low",
      "attacker_ips": ["ip1", "ip2", "ip3"],
      "description": "Brief 2-3 sentence description",
      "mitre_techniques": ["T1046", "T1190"]
    }
    
    Be specific and accurate. Use the evidence from the analysis context to support your classification.
    If uncertain, explain your reasoning but still provide a classification.
    """,
    tools=[analyze_attack_patterns]
)

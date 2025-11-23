# ============================================================================
# agents/log_parser/agent.py
# Log Parser Agent - Analyzes security logs
# ============================================================================

import os
import json
import base64
import re
from collections import defaultdict
import ipaddress
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


def parse_logs(log_base64: str, max_lines: int = 5000) -> str:
    """
    Parse log file and extract security events and IOCs.
    
    Args:
        log_base64: Base64 encoded log file content
        max_lines: Maximum number of lines to process
        
    Returns:
        JSON string with parsing results
    """
    try:
        # Decode base64 to text
        log_text = base64.b64decode(log_base64).decode('utf-8', errors='ignore')
        lines = log_text.split('\n')[:max_lines]
        
        # Regex patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        
        # Analysis structures
        ips_seen = defaultdict(int)
        domains_seen = defaultdict(int)
        attack_keywords = ['sql', 'xss', 'injection', 'exploit', 'malware', 
                          'attack', 'scan', 'brute', 'unauthorized', 'intrusion',
                          'vulnerability', 'payload', 'shell', 'backdoor']
        
        suspicious_events = []
        iocs = []
        
        # Process lines
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Check for attack keywords
            found_keywords = [kw for kw in attack_keywords if kw in line_lower]
            if found_keywords:
                suspicious_events.append({
                    'line_number': line_num,
                    'keywords': found_keywords,
                    'excerpt': line[:200]
                })
            
            # Extract IPs
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                ips_seen[ip] += 1
            
            # Extract domains
            domains = re.findall(domain_pattern, line_lower)
            for domain in domains:
                if '.' in domain and len(domain) > 4:
                    domains_seen[domain] += 1
        
        # Create IOCs from IPs
        for ip, count in ips_seen.items():
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback):
                    iocs.append({
                        'type': 'ip',
                        'value': ip,
                        'context': {
                            'occurrences': count,
                            'source': 'logs'
                        }
                    })
            except:
                pass
        
        # Create IOCs from domains
        for domain, count in domains_seen.items():
            iocs.append({
                'type': 'domain',
                'value': domain,
                'context': {
                    'occurrences': count,
                    'source': 'logs'
                }
            })
        
        results = {
            'status': 'success',
            'stats': {
                'total_lines': len(lines),
                'unique_ips': len(ips_seen),
                'unique_domains': len(domains_seen),
                'suspicious_events': len(suspicious_events)
            },
            'suspicious_events': suspicious_events[:50],  # Limit output
            'iocs': iocs
        }
        
        return json.dumps(results)
        
    except Exception as e:
        return json.dumps({
            'status': 'error',
            'error': str(e)
        })


# Create the Log Parser Agent
root_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="log_parser_agent",
    description="Analyzes security log files to extract events and indicators of compromise (IOCs).",
    instruction="""
    You are a security log analysis specialist. When given a base64-encoded log file:
    
    1. Use the parse_logs tool to analyze the log content
    2. Return the complete analysis including:
       - Log statistics (lines processed, IPs, domains)
       - Suspicious events with keywords and context
       - Extracted IOCs with occurrence counts
    
    Always call the parse_logs tool and return its complete output.
    Be thorough in identifying potential security issues.
    """,
    tools=[parse_logs]
)

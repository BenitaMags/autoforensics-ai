# ============================================================================
# agents/pcap_parser/agent.py
# PCAP Parser Agent - Analyzes network traffic
# ============================================================================

import os
import json
import base64
from collections import defaultdict
from typing import Dict, List, Tuple
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


def parse_pcap(pcap_base64: str, max_packets: int = 2000) -> str:
    """
    Parse PCAP file and extract network statistics and IOCs.
    
    Args:
        pcap_base64: Base64 encoded PCAP file content
        max_packets: Maximum number of packets to process
        
    Returns:
        JSON string with parsing results
    """
    try:
        # Lazy import to avoid loading unless needed
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS
        import tempfile
        import ipaddress
        
        # Decode base64 to bytes
        pcap_bytes = base64.b64decode(pcap_base64)
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name
        
        # Parse PCAP
        packets = scapy.rdpcap(tmp_path)
        packet_count = min(len(packets), max_packets)
        
        # Clean up temp file
        os.unlink(tmp_path)
        
        # Analysis structures
        flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'ports': set()})
        ips_seen = defaultdict(int)
        domains_seen = defaultdict(int)
        suspicious_ports = defaultdict(int)
        iocs = []
        
        # Process packets
        for i, pkt in enumerate(packets[:packet_count]):
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                ips_seen[src_ip] += 1
                ips_seen[dst_ip] += 1
                
                flow_key = f"{src_ip}:{dst_ip}"
                flows[flow_key]['packets'] += 1
                flows[flow_key]['bytes'] += len(pkt)
                
                # Check for suspicious ports
                if TCP in pkt:
                    dport = pkt[TCP].dport
                    flows[flow_key]['ports'].add(dport)
                    
                    if dport in [4444, 5555, 6666, 8888, 31337]:
                        suspicious_ports[dst_ip] += 1
            
            # Extract DNS queries
            if DNS in pkt and pkt[DNS].qr == 0:
                if pkt[DNS].qd:
                    domain = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
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
                            'connection_count': count,
                            'suspicious_ports': suspicious_ports.get(ip, 0),
                            'source': 'pcap'
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
                    'query_count': count,
                    'source': 'pcap'
                }
            })
        
        results = {
            'status': 'success',
            'stats': {
                'total_packets': packet_count,
                'unique_ips': len(ips_seen),
                'unique_domains': len(domains_seen),
                'suspicious_ports_detected': len(suspicious_ports),
                'flows': len(flows)
            },
            'iocs': iocs
        }
        
        return json.dumps(results)
        
    except Exception as e:
        return json.dumps({
            'status': 'error',
            'error': str(e)
        })


# Create the PCAP Parser Agent
root_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="pcap_parser_agent",
    description="Analyzes PCAP files to extract network statistics and indicators of compromise (IOCs).",
    instruction="""
    You are a PCAP analysis specialist. When given a base64-encoded PCAP file:
    
    1. Use the parse_pcap tool to analyze the network traffic
    2. Return the complete analysis including:
       - Network statistics (packets, IPs, domains, flows)
       - Extracted IOCs with context
       - Any suspicious activity detected
    
    Always call the parse_pcap tool and return its complete output.
    Be thorough and accurate in your analysis.
    """,
    tools=[parse_pcap]
)

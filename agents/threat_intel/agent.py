# ============================================================================
# agents/threat_intel/agent.py
# Threat Intelligence Agent - Enriches high-value IOCs only
# ============================================================================

import os
import json
import requests
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

# API Keys from environment
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

# Enrichment thresholds - ONLY enrich IOCs meeting these criteria
ENRICHMENT_THRESHOLDS = {
    'min_score': 0.6,  # IOC must score >= 0.6
    'max_iocs': 50,    # Maximum IOCs to enrich per batch
    'priority_types': ['ip', 'domain', 'hash']  # Types worth enriching
}


def should_enrich_ioc(ioc: Dict) -> bool:
    """
    Determine if an IOC is worth enriching with threat intelligence.
    
    Only enrich if:
    1. Score is high enough (>= 0.6)
    2. Type is in priority list
    3. Context indicates suspicious activity
    
    Args:
        ioc: IOC dictionary with type, value, score, context
        
    Returns:
        True if IOC should be enriched, False otherwise
    """
    score = ioc.get('score', 0.0)
    ioc_type = ioc.get('type', '')
    context = ioc.get('context', {})
    
    # Check minimum score threshold
    if score < ENRICHMENT_THRESHOLDS['min_score']:
        return False
    
    # Check if type is worth enriching
    if ioc_type not in ENRICHMENT_THRESHOLDS['priority_types']:
        return False
    
    # Additional context checks
    if ioc_type == 'ip':
        # High connection count or suspicious ports
        conn_count = context.get('connection_count', 0) + context.get('occurrences', 0)
        suspicious_ports = context.get('suspicious_ports', 0)
        if conn_count < 10 and suspicious_ports == 0:
            return False
    
    elif ioc_type == 'domain':
        # High query count
        query_count = context.get('query_count', 0) + context.get('occurrences', 0)
        if query_count < 5:
            return False
    
    return True


def enrich_iocs(gated_iocs_json: str) -> str:
    """
    Selectively enrich only high-value IOCs with threat intelligence.
    
    This function implements smart filtering:
    1. Evaluates each IOC against enrichment thresholds
    2. Only calls APIs for IOCs that meet criteria
    3. Caches results to avoid duplicate lookups
    4. Returns enriched IOCs with provenance
    
    Args:
        gated_iocs_json: JSON string with gated IOCs
        
    Returns:
        JSON string with enrichment results
    """
    try:
        data = json.loads(gated_iocs_json)
        gated_iocs = data.get('gated_iocs', [])
        
        # Filter IOCs worth enriching
        iocs_to_enrich = [
            ioc for ioc in gated_iocs 
            if should_enrich_ioc(ioc)
        ][:ENRICHMENT_THRESHOLDS['max_iocs']]
        
        # Track statistics
        stats = {
            'total_iocs': len(gated_iocs),
            'evaluated_for_enrichment': len(gated_iocs),
            'qualified_for_enrichment': len(iocs_to_enrich),
            'actually_enriched': 0,
            'skipped_low_value': len(gated_iocs) - len(iocs_to_enrich),
            'api_calls_made': 0,
            'api_calls_saved': 0,
            'cache_hits': 0
        }
        
        # If no IOCs qualify, return early
        if not iocs_to_enrich:
            return json.dumps({
                'status': 'success',
                'message': 'No IOCs met enrichment thresholds - saved API calls!',
                'stats': stats,
                'enriched_iocs': [],
                'skipped_iocs': [
                    {
                        'value': ioc['value'],
                        'score': ioc['score'],
                        'reason': f"Score {ioc['score']} < threshold {ENRICHMENT_THRESHOLDS['min_score']}"
                    }
                    for ioc in gated_iocs[:10]  # Sample
                ]
            })
        
        # Cache for deduplication
        enrichment_cache = {}
        enriched_results = []
        
        # Enrich qualified IOCs
        for ioc in iocs_to_enrich:
            cache_key = f"{ioc['type']}:{ioc['value']}"
            
            # Check cache
            if cache_key in enrichment_cache:
                enrichment = enrichment_cache[cache_key]
                stats['cache_hits'] += 1
            else:
                # Call threat intel APIs
                enrichment = enrich_single_ioc(ioc)
                enrichment_cache[cache_key] = enrichment
                stats['api_calls_made'] += enrichment.get('api_calls', 0)
            
            # Add enrichment to IOC
            enriched_ioc = ioc.copy()
            enriched_ioc['enrichment'] = enrichment
            enriched_results.append(enriched_ioc)
            stats['actually_enriched'] += 1
        
        # Calculate savings
        potential_calls = len(gated_iocs) * 3  # Average 3 APIs per IOC
        stats['api_calls_saved'] = potential_calls - stats['api_calls_made']
        stats['efficiency'] = f"{(stats['api_calls_saved'] / potential_calls * 100):.1f}%" if potential_calls > 0 else "N/A"
        
        return json.dumps({
            'status': 'success',
            'stats': stats,
            'enriched_iocs': enriched_results,
            'threshold_info': {
                'min_score': ENRICHMENT_THRESHOLDS['min_score'],
                'max_batch': ENRICHMENT_THRESHOLDS['max_iocs'],
                'apis_available': {
                    'virustotal': bool(VIRUSTOTAL_API_KEY),
                    'abuseipdb': bool(ABUSEIPDB_API_KEY),
                    'shodan': bool(SHODAN_API_KEY)
                }
            }
        })
        
    except Exception as e:
        return json.dumps({
            'status': 'error',
            'error': str(e)
        })


def enrich_single_ioc(ioc: Dict) -> Dict:
    """
    Enrich a single IOC using available threat intelligence APIs.
    
    Args:
        ioc: IOC dictionary
        
    Returns:
        Enrichment data dictionary
    """
    ioc_type = ioc['type']
    value = ioc['value']
    
    enrichment = {
        'reputation_score': 0.0,
        'verdict': 'unknown',
        'sources': [],
        'api_calls': 0,
        'findings': []
    }
    
    # Try VirusTotal
    if VIRUSTOTAL_API_KEY and ioc_type in ['ip', 'domain', 'hash']:
        vt_result = query_virustotal(ioc_type, value)
        if vt_result:
            enrichment['sources'].append('VirusTotal')
            enrichment['findings'].append(vt_result)
            enrichment['reputation_score'] += vt_result.get('score', 0.0)
            enrichment['api_calls'] += 1
    
    # Try AbuseIPDB for IPs
    if ABUSEIPDB_API_KEY and ioc_type == 'ip':
        abuse_result = query_abuseipdb(value)
        if abuse_result:
            enrichment['sources'].append('AbuseIPDB')
            enrichment['findings'].append(abuse_result)
            enrichment['reputation_score'] += abuse_result.get('score', 0.0)
            enrichment['api_calls'] += 1
    
    # Try Shodan for IPs
    if SHODAN_API_KEY and ioc_type == 'ip':
        shodan_result = query_shodan(value)
        if shodan_result:
            enrichment['sources'].append('Shodan')
            enrichment['findings'].append(shodan_result)
            enrichment['api_calls'] += 1
    
    # Calculate final verdict
    if not enrichment['sources']:
        # Simulate enrichment if no APIs available
        enrichment = simulate_enrichment(ioc)
    else:
        avg_score = enrichment['reputation_score'] / len(enrichment['sources'])
        if avg_score > 0.7:
            enrichment['verdict'] = 'malicious'
        elif avg_score > 0.4:
            enrichment['verdict'] = 'suspicious'
        else:
            enrichment['verdict'] = 'clean'
    
    return enrichment


def query_virustotal(ioc_type: str, value: str) -> Dict:
    """Query VirusTotal API"""
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        if ioc_type == 'ip':
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{value}'
        elif ioc_type == 'domain':
            url = f'https://www.virustotal.com/api/v3/domains/{value}'
        elif ioc_type == 'hash':
            url = f'https://www.virustotal.com/api/v3/files/{value}'
        else:
            return None
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            
            score = (malicious + suspicious * 0.5) / total
            
            return {
                'source': 'VirusTotal',
                'score': score,
                'detections': f"{malicious}/{total}",
                'details': stats
            }
    except:
        pass
    
    return None


def query_abuseipdb(ip: str) -> Dict:
    """Query AbuseIPDB API"""
    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            abuse_score = data.get('abuseConfidenceScore', 0) / 100
            
            return {
                'source': 'AbuseIPDB',
                'score': abuse_score,
                'reports': data.get('totalReports', 0),
                'categories': data.get('usageType', 'Unknown')
            }
    except:
        pass
    
    return None


def query_shodan(ip: str) -> Dict:
    """Query Shodan API"""
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}'
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            return {
                'source': 'Shodan',
                'open_ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'organization': data.get('org', 'Unknown'),
                'country': data.get('country_name', 'Unknown')
            }
    except:
        pass
    
    return None


def simulate_enrichment(ioc: Dict) -> Dict:
    """Simulate enrichment when APIs are unavailable"""
    score = ioc.get('score', 0.5)
    
    # Simulate based on IOC score
    reputation = min(score * 1.2, 1.0)
    
    if reputation > 0.7:
        verdict = 'malicious'
    elif reputation > 0.4:
        verdict = 'suspicious'
    else:
        verdict = 'clean'
    
    return {
        'reputation_score': reputation,
        'verdict': verdict,
        'sources': ['Local Analysis'],
        'api_calls': 0,
        'findings': [{
            'source': 'Simulated',
            'note': 'Real APIs not configured - using score-based estimation'
        }]
    }


# Create the Threat Intelligence Agent
root_agent = LlmAgent(
    model=Gemini(model="gemini-2.0-flash-exp", retry_options=retry_config),
    name="threat_intel_agent",
    description="Selectively enriches high-value IOCs with threat intelligence from VirusTotal, AbuseIPDB, and Shodan",
    instruction="""
    You are a threat intelligence specialist that ONLY enriches IOCs that meet quality thresholds.
    
    Your intelligence:
    1. Evaluate which IOCs are worth enriching (score >= 0.6, suspicious activity)
    2. Call enrich_iocs tool which automatically filters and enriches
    3. Return enrichment results WITH efficiency statistics
    
    Key metrics to report:
    - How many IOCs qualified for enrichment
    - How many API calls were made
    - How many API calls were SAVED by smart filtering
    - Enrichment efficiency percentage
    
    The tool is designed to MAXIMIZE API efficiency by:
    - Only enriching IOCs scoring >= 0.6
    - Skipping low-value indicators
    - Caching results to avoid duplicates
    - Limiting batch size to 50 IOCs max
    
    Always explain WHY IOCs were or weren't enriched based on threshold criteria.
    Highlight the API cost savings achieved through intelligent filtering.
    """,
    tools=[enrich_iocs]
)

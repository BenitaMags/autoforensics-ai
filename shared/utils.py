# ============================================================================
# shared/utils.py
# Helper functions
# ============================================================================

import json
import hashlib
import ipaddress
from typing import List, Dict, Any


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0
    entropy = 0
    for c in set(s):
        p = s.count(c) / len(s)
        entropy -= p * (p and (p * 0.30103))
    return entropy


def is_public_ip(ip: str) -> bool:
    """Check if IP is public (not private/reserved)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or 
                   ip_obj.is_reserved or ip_obj.is_multicast)
    except:
        return False


def hash_file(filepath: str) -> str:
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def deduplicate_iocs(iocs: List[IOC]) -> List[IOC]:
    """Remove duplicate IOCs, keeping the one with most context"""
    seen = {}
    for ioc in iocs:
        key = f"{ioc.type}:{ioc.value}"
        if key not in seen:
            seen[key] = ioc
        else:
            # Merge contexts
            seen[key].context.update(ioc.context)
    return list(seen.values())


def safe_json_loads(text: str) -> Dict:
    """Safely parse JSON from LLM response"""
    try:
        # Remove markdown code blocks if present
        if '```json' in text:
            text = text.split('```json')[1].split('```')[0]
        elif '```' in text:
            text = text.split('```')[1].split('```')[0]
        
        return json.loads(text.strip())
    except Exception as e:
        raise ValueError(f"Failed to parse JSON: {e}\nText: {text[:200]}")


def format_timestamp(dt: datetime = None) -> str:
    """Format timestamp for display"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

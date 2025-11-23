# ============================================================================
# shared/constants.py
# Configuration constants
# ============================================================================

# Model configuration
DEFAULT_MODEL = "gemini-2.0-flash-exp"
FALLBACK_MODEL = "gemini-1.5-flash"

# Analysis limits
MAX_PACKETS = 2000
MAX_LOG_LINES = 5000
MAX_API_CALLS = 300

# IOC Gating
IOC_GATE_THRESHOLD = 0.4
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
SUSPICIOUS_KEYWORDS = ['malware', 'exploit', 'hack', 'phish', 'evil', 
                      'bad', 'attack', 'c2', 'command']

# Trusted domains (low score)
TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'amazon.com', 'apple.com',
                   'cloudflare.com', 'akamai.com', 'github.com']

# API retry configuration
RETRY_CONFIG = {
    'attempts': 5,
    'exp_base': 7,
    'initial_delay': 1,
    'http_status_codes': [429, 500, 503, 504]
}

# Agent Engine configuration
AGENT_ENGINE_CONFIG = {
    "min_instances": 0,
    "max_instances": 2,
    "resource_limits": {"cpu": "2", "memory": "2Gi"}
}

# Available regions for deployment
AVAILABLE_REGIONS = ["us-central1", "us-east4", "us-west1", "europe-west1", "europe-west4"]

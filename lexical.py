import re
from urllib.parse import urlparse

def lexical_score(url: str) -> dict:
    """
    Returns a dictionary with basic lexical features and a risk score.
    """
    features = {}
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Feature: length of URL
    features['length'] = len(url)
    # Feature: count of digits
    features['digits'] = sum(c.isdigit() for c in url)
    # Feature: count of special chars
    features['special_chars'] = sum(1 for c in url if not c.isalnum())
    # Feature: number of subdomains
    features['subdomains'] = hostname.count('.')
    # Detect IP address
    features['is_ip'] = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))

    # Simple heuristic risk scoring (tune weights as needed)
    score = 0
    score += features['length'] > 75
    score += features['digits'] > 5
    score += features['special_chars'] > 10
    score += features['subdomains'] > 3
    score += features['is_ip']
    features['risk_score'] = int(score / 5 * 100)

    return features
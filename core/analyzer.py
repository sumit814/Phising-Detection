import re
import socket
import ssl
import idna
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Optional

class URLAnalyzer:
    """Handles heuristic analysis of URLs for phishing indicators"""
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    TOP_DOMAINS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal']
    
    def __init__(self):
        self._entropy_cache = {}

    def analyze(self, url: str) -> Dict[str, Any]:
        """Main analysis function"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        features = {
            'basic': self._basic_checks(url, domain),
            'advanced': self._advanced_checks(domain),
            'security': self._security_checks(url, domain),
            'domain': self._domain_analysis(domain)
        }
        
        return features

    def _basic_checks(self, url: str, domain: str) -> Dict[str, bool]:
        """Basic URL structure checks"""
        return {
            'has_ip': bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            'has_https': url.startswith('https://'),
            'shortened': any(short in domain for short in ['bit.ly', 'tinyurl.com']),
            'suspicious_tld': any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS),
            'many_hyphens': domain.count('-') > 3,
            'many_subdomains': domain.count('.') > 3,
            'is_encoded': '%' in url
        }

    def _advanced_checks(self, domain: str) -> Dict[str, bool]:
        """Advanced heuristic checks"""
        return {
            'typosquatting': self._check_typosquatting(domain),
            'homograph': self._check_homograph(domain),
            'high_entropy': self._calculate_entropy(domain) > 3.5
        }

    def _security_checks(self, url: str, domain: str) -> Dict[str, Any]:
        """Security-related checks"""
        return {
            'ssl_valid': self._check_ssl(url),
            'redirects': self._check_redirects(url)
        }

    def _domain_analysis(self, domain: str) -> Dict[str, Any]:
        """Domain-specific analysis"""
        return {
            'length': len(domain),
            'digit_ratio': sum(c.isdigit() for c in domain) / len(domain),
            'symbol_ratio': sum(not c.isalnum() for c in domain) / len(domain)
        }

    def _check_typosquatting(self, domain: str) -> bool:
        """Check for domain impersonation"""
        clean_domain = re.sub(r'\.(com|net|org)$', '', domain.lower())
        for legit in self.TOP_DOMAINS:
            if self._levenshtein(clean_domain, legit) <= 2:
                return True
        return False

    def _check_homograph(self, domain: str) -> bool:
        """Detect homograph attacks"""
        try:
            decoded = idna.decode(domain)
            return any(ord(c) > 128 for c in decoded)
        except:
            return False

    def _check_ssl(self, url: str) -> bool:
        """Verify SSL certificate"""
        hostname = urlparse(url).netloc.split(':')[0]
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        return expire_date > datetime.now()
            return False
        except:
            return False

    def _check_redirects(self, url: str) -> Dict[str, Any]:
        """Analyze redirect chain"""
        try:
            import requests
            response = requests.head(url, allow_redirects=True, timeout=5)
            return {
                'final_url': response.url,
                'redirect_count': len(response.history),
                'domain_changed': urlparse(url).netloc != urlparse(response.url).netloc
            }
        except:
            return {'error': 'redirect check failed'}

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance"""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if text in self._entropy_cache:
            return self._entropy_cache[text]
            
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        self._entropy_cache[text] = entropy
        return entropy

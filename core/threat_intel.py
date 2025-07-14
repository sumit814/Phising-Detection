import requests
import json
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime

class ThreatIntelligence:
    """Handles threat intelligence API integrations"""
    
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.cache = {}

    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against all threat feeds"""
        domain = urlparse(url).netloc
        cache_key = hashlib.md5(domain.encode()).hexdigest()
        
        if cache_key in self.cache:
            return self.cache[cache_key]
            
        results = {
            'phishtank': self._check_phishtank(url),
            'google_safe_browsing': self._check_google_safe_browsing(url),
            'virustotal': self._check_virustotal(url),
            'timestamp': datetime.now().isoformat()
        }
        
        self.cache[cache_key] = results
        return results

    def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check PhishTank database"""
        if not self.api_keys.get('phishtank'):
            return {'error': 'API key not configured'}
            
        try:
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url': url,
                    'format': 'json',
                    'app_key': self.api_keys['phishtank']
                },
                timeout=5
            )
            data = response.json()
            return {
                'in_database': data.get('results', {}).get('in_database', False),
                'verified': data.get('results', {}).get('verified', False),
                'details': data.get('results', {}).get('phish_detail_page', '')
            }
        except Exception as e:
            return {'error': str(e)}

    def _check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check Google Safe Browsing API"""
        if not self.api_keys.get('google_safe_browsing'):
            return {'error': 'API key not configured'}
            
        try:
            headers = {'Content-Type': 'application/json'}
            payload = {
                "client": {
                    "clientId": "phishing-detector",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_keys['google_safe_browsing']}",
                headers=headers,
                data=json.dumps(payload),
                timeout=5
            )
            
            data = response.json()
            return {
                'malicious': 'matches' in data,
                'details': data.get('matches', [])
            }
        except Exception as e:
            return {'error': str(e)}

    def _check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check VirusTotal API"""
        if not self.api_keys.get('virustotal'):
            return {'error': 'API key not configured'}
            
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            # First submit URL for scanning
            scan_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=5
            )
            scan_id = scan_response.json().get('data', {}).get('id')
            
            # Then get the report
            report_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{scan_id}',
                headers=headers,
                timeout=5
            )
            
            data = report_response.json()
            stats = data.get('data', {}).get('attributes', {}).get('stats', {})
            return {
                'malicious': stats.get('malicious', 0) > 0,
                'stats': stats,
                'permalink': data.get('data', {}).get('links', {}).get('item', '')
            }
        except Exception as e:
            return {'error': str(e)}

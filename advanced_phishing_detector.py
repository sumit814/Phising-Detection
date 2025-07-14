#!/usr/bin/env python3
"""
Advanced Phishing URL Detection System
-------------------------------------
Features:
1. Multi-layer URL analysis
2. Threat intelligence integration
3. Machine learning detection
4. SSL/TLS certificate validation
5. WHOIS domain analysis
6. Typo-squatting detection
7. Homograph attack detection
8. Short URL expansion
9. Comprehensive reporting
"""

import re
import socket
import ssl
import json
import time
import requests
import whois
import tldextract
import numpy as np
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse, urlunparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import logging
import hashlib
import idna
import concurrent.futures
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phish_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ========================
# CONSTANTS & CONFIGURATION
# ========================
class Config:
    # Suspicious patterns
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'rebrand.ly']
    TOP_LEGIT_DOMAINS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'bankofamerica']
    
    # Thresholds
    RISK_HIGH = 0.7
    RISK_MEDIUM = 0.4
    MAX_REDIRECTS = 5
    MAX_HYPHENS = 3
    MAX_DOMAIN_AGE_DAYS = 30
    
    # API Keys (should be in environment variables in production)
    PHISHTANK_API_KEY = None
    GOOGLE_SAFE_BROWSING_API_KEY = None
    VIRUSTOTAL_API_KEY = None

# ========================
# CORE DETECTION CLASS
# ========================
class AdvancedPhishingDetector:
    def __init__(self):
        self.ml_model = self._load_ml_model()
        self.vectorizer = self._load_vectorizer()
        self.session = requests.Session()
        self.session.max_redirects = Config.MAX_REDIRECTS
        self.cache = {}  # Simple cache for demonstration
        
    # ========================
    # MODEL MANAGEMENT
    # ========================
    def _load_ml_model(self):
        """Load pre-trained ML model"""
        try:
            model = joblib.load('models/phishing_model.pkl')
            logger.info("ML model loaded successfully")
            return model
        except Exception as e:
            logger.warning(f"Failed to load ML model: {str(e)}")
            return None
            
    def _load_vectorizer(self):
        """Load feature vectorizer"""
        try:
            vectorizer = joblib.load('models/tfidf_vectorizer.pkl')
            logger.info("Feature vectorizer loaded successfully")
            return vectorizer
        except Exception as e:
            logger.warning(f"Failed to load vectorizer: {str(e)}")
            return None

    # ========================
    # URL VALIDATION & PARSING
    # ========================
    def is_valid_url(self, url):
        """Validate URL format using multiple methods"""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
                
            # Check for valid domain
            extracted = tldextract.extract(url)
            if not extracted.domain or not extracted.suffix:
                return False
                
            # Check for illegal characters
            if re.search(r'[\s<>{}|\\^~\[\]]', url):
                return False
                
            return True
        except:
            return False

    def normalize_url(self, url):
        """Normalize URL for consistent processing"""
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return urlunparse(parsed._replace(path=parsed.path.rstrip('/')))

    # ========================
    # BASIC URL FEATURES
    # ========================
    def extract_basic_features(self, url):
        """Extract basic URL features for analysis"""
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': domain.count('.'),
            'num_hyphens': domain.count('-'),
            'num_underscore': domain.count('_'),
            'num_slash': url.count('/'),
            'num_question': url.count('?'),
            'num_equal': url.count('='),
            'num_at': url.count('@'),
            'num_ampersand': url.count('&'),
            'num_percent': url.count('%'),
            'has_ip': bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            'has_https': url.startswith('https://'),
            'shortened': any(short in domain for short in Config.SHORTENERS),
            'suspicious_tld': any(domain.endswith(tld) for tld in Config.SUSPICIOUS_TLDS),
            'digit_count': sum(c.isdigit() for c in domain),
            'letter_count': sum(c.isalpha() for c in domain),
            'symbol_count': sum(not c.isalnum() for c in domain),
            'entropy': self._calculate_entropy(domain),
            'path_length': len(path),
            'query_length': len(parsed.query),
            'fragment_length': len(parsed.fragment),
            'is_encoded': '%' in url,
            'port_present': ':' in domain and domain.split(':')[1].isdigit(),
        }
        return features

    # ========================
    # ADVANCED DETECTION METHODS
    # ========================
    def check_typosquatting(self, domain):
        """Detect typosquatting using multiple methods"""
        domain_clean = re.sub(r'\.(com|net|org|edu|gov)$', '', domain.lower())
        
        # Levenshtein distance
        for legit in Config.TOP_LEGIT_DOMAINS:
            if self._levenshtein_distance(domain_clean, legit) <= 2:
                return True
                
        # Character omission
        for legit in Config.TOP_LEGIT_DOMAINS:
            if legit in domain_clean and len(domain_clean) - len(legit) == 1:
                return True
                
        # Common misspellings
        misspellings = {
            'google': ['go0gle', 'g00gle', 'googel'],
            'paypal': ['paypai', 'paypa1', 'paypol']
        }
        
        for legit, variants in misspellings.items():
            if legit in domain_clean:
                for variant in variants:
                    if variant in domain_clean:
                        return True
        return False

    def detect_homograph_attack(self, url):
        """Detect possible homograph attacks using IDNA"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            idna_decoded = idna.decode(domain)
            
            # Check for mixed scripts
            latin = any(ord(c) < 128 for c in idna_decoded)
            non_latin = any(ord(c) >= 128 for c in idna_decoded)
            
            if latin and non_latin:
                return True
                
            # Check for visually similar characters
            suspicious_chars = set('аеіоурсԁһјӏорѕυѵѡхуҽᴦ')
            if any(c in idna_decoded for c in suspicious_chars):
                return True
                
            return False
        except:
            return False

    def analyze_redirect_chain(self, url):
        """Follow redirects and analyze the chain"""
        try:
            redirects = []
            current_url = url
            seen_urls = set()
            
            for _ in range(Config.MAX_REDIRECTS):
                if current_url in seen_urls:
                    break
                seen_urls.add(current_url)
                
                response = self.session.head(current_url, allow_redirects=False, timeout=5)
                if 300 <= response.status_code < 400:
                    next_url = response.headers.get('location')
                    if next_url:
                        redirects.append({
                            'from': current_url,
                            'to': next_url,
                            'status': response.status_code
                        })
                        current_url = next_url
                    else:
                        break
                else:
                    break
                    
            # Analyze redirect chain
            suspicious = False
            reasons = []
            
            if len(redirects) > 3:
                suspicious = True
                reasons.append("Too many redirects (>3)")
                
            final_domain = urlparse(redirects[-1]['to']).netloc if redirects else urlparse(url).netloc
            initial_domain = urlparse(url).netloc
            
            if final_domain != initial_domain:
                suspicious = True
                reasons.append("Domain switch in redirects")
                
            return {
                'count': len(redirects),
                'chain': redirects,
                'suspicious': suspicious,
                'reasons': reasons,
                'final_url': redirects[-1]['to'] if redirects else url
            }
        except:
            return {
                'count': 0,
                'chain': [],
                'suspicious': False,
                'reasons': [],
                'final_url': url
            }

    # ========================
    # SECURITY CHECKS
    # ========================
    def check_ssl_certificate(self, url):
        """Verify SSL/TLS certificate validity"""
        hostname = urlparse(url).netloc.split(':')[0]
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        expired = expire_date < datetime.now()
                    else:
                        expired = True
                        
                    # Check subject
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    return {
                        'valid': not expired,
                        'expired': expired,
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'sigAlg': cert.get('signatureAlgorithm'),
                        'keySize': cert.get('keySize', 'unknown')
                    }
        except Exception as e:
            logger.error(f"SSL check failed: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }

    def get_whois_info(self, url):
        """Get WHOIS domain information"""
        domain = urlparse(url).netloc
        
        try:
            w = whois.whois(domain)
            
            # Handle creation date (can be list or single value)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            # Calculate domain age
            age_days = None
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                
            return {
                'domain': domain,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': str(creation_date) if creation_date else None,
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': list(w.name_servers) if w.name_servers else None,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country,
                'age_days': age_days,
                'suspicious_age': age_days is not None and age_days < Config.MAX_DOMAIN_AGE_DAYS
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            return {
                'error': str(e)
            }

    # ========================
    # THREAT INTELLIGENCE
    # ========================
    def query_threat_feeds(self, url):
        """Check URL against multiple threat intelligence feeds"""
        results = {}
        
        # PhishTank
        results['PhishTank'] = self._check_phishtank(url)
        
        # Google Safe Browsing (mock implementation)
        results['GoogleSafeBrowsing'] = self._check_google_safe_browsing(url)
        
        # VirusTotal (mock implementation)
        results['VirusTotal'] = self._check_virustotal(url)
        
        return results

    def _check_phishtank(self, url):
        """Check URL against PhishTank database"""
        try:
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url': url,
                    'format': 'json',
                    'app_key': Config.PHISHTANK_API_KEY or ''
                },
                timeout=5
            )
            data = response.json()
            return {
                'in_database': data.get('results', {}).get('in_database', False),
                'verified': data.get('results', {}).get('verified', False),
                'phish_detail_page': data.get('results', {}).get('phish_detail_page', '')
            }
        except Exception as e:
            logger.error(f"PhishTank check failed: {str(e)}")
            return {'error': str(e)}

    # ========================
    # MACHINE LEARNING
    # ========================
    def ml_predict(self, url_features):
        """Make prediction using ML model"""
        if not self.ml_model or not self.vectorizer:
            return None
            
        try:
            # Convert features to string representation
            features_str = ' '.join([f'{k}_{v}' for k,v in url_features.items()])
            X = self.vectorizer.transform([features_str])
            proba = self.ml_model.predict_proba(X)[0]
            return {
                'prediction': self.ml_model.predict(X)[0],
                'probability_phishing': proba[1],
                'probability_benign': proba[0]
            }
        except Exception as e:
            logger.error(f"ML prediction failed: {str(e)}")
            return None

    # ========================
    # UTILITY METHODS
    # ========================
    def _levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
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

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy

    # ========================
    # MAIN ANALYSIS METHOD
    # ========================
    def analyze_url(self, url):
        """Comprehensive URL analysis with all features"""
        start_time = time.time()
        
        # Validate and normalize URL
        if not self.is_valid_url(url):
            return {
                'error': 'Invalid URL format',
                'valid': False
            }
            
        normalized_url = self.normalize_url(url)
        
        # Check cache
        cache_key = hashlib.md5(normalized_url.encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]
            
        # Initialize result structure
        result = {
            'url': normalized_url,
            'valid': True,
            'analysis_time': None,
            'basic_features': None,
            'advanced_checks': None,
            'security_checks': None,
            'threat_intelligence': None,
            'ml_analysis': None,
            'risk_score': 0,
            'verdict': 'clean'
        }
        
        # 1. Basic feature extraction
        basic_features = self.extract_basic_features(normalized_url)
        result['basic_features'] = basic_features
        
        # 2. Advanced checks
        advanced_checks = {
            'typosquatting': self.check_typosquatting(urlparse(normalized_url).netloc),
            'homograph_attack': self.detect_homograph_attack(normalized_url),
            'redirect_analysis': self.analyze_redirect_chain(normalized_url)
        }
        result['advanced_checks'] = advanced_checks
        
        # 3. Security checks
        security_checks = {
            'ssl_certificate': self.check_ssl_certificate(normalized_url),
            'whois_info': self.get_whois_info(normalized_url)
        }
        result['security_checks'] = security_checks
        
        # 4. Threat intelligence
        result['threat_intelligence'] = self.query_threat_feeds(normalized_url)
        
        # 5. Machine learning analysis
        if self.ml_model:
            ml_result = self.ml_predict(basic_features)
            result['ml_analysis'] = ml_result
        
        # Calculate comprehensive risk score
        risk_score = self._calculate_risk_score(result)
        result['risk_score'] = risk_score
        result['verdict'] = self._determine_verdict(risk_score)
        
        # Add timing information
        result['analysis_time'] = time.time() - start_time
        
        # Cache result
        self.cache[cache_key] = result
        
        return result

    def _calculate_risk_score(self, analysis_result):
        """Calculate comprehensive risk score (0-1)"""
        score = 0.0
        
        # Basic features
        features = analysis_result['basic_features']
        if features['has_ip']: score += 0.15
        if features['suspicious_tld']: score += 0.10
        if not features['has_https']: score += 0.10
        if features['shortened']: score += 0.05
        if features['entropy'] > 4: score += 0.05
        
        # Advanced checks
        advanced = analysis_result['advanced_checks']
        if advanced['typosquatting']: score += 0.15
        if advanced['homograph_attack']: score += 0.15
        if advanced['redirect_analysis']['suspicious']: score += 0.10
        
        # Security checks
        security = analysis_result['security_checks']
        if not security['ssl_certificate'].get('valid', False): score += 0.10
        if security['whois_info'].get('suspicious_age', False): score += 0.05
        
        # Threat intelligence
        threats = analysis_result['threat_intelligence']
        if threats['PhishTank'].get('in_database', False): score += 0.30
        if threats['GoogleSafeBrowsing'].get('malicious', False): score += 0.25
        if threats['VirusTotal'].get('positives', 0) > 0: score += 0.20
        
        # ML prediction
        if analysis_result['ml_analysis']:
            ml_score = analysis_result['ml_analysis']['probability_phishing']
            score += ml_score * 0.5  # Weight ML prediction
        
        return min(score, 1.0)

    def _determine_verdict(self, risk_score):
        """Determine final verdict based on risk score"""
        if risk_score >= Config.RISK_HIGH:
            return 'malicious'
        elif risk_score >= Config.RISK_MEDIUM:
            return 'suspicious'
        else:
            return 'clean'

# ========================
# MAIN EXECUTION
# ========================
if __name__ == "__main__":
    detector = AdvancedPhishingDetector()
    
    test_urls = [
        "https://www.google.com",
        "http://paypal-security-update.com",
        "https://bit.ly/3xYmF4d",
        "https://www.xn--ggle-0qga.com",  # Homograph example
        "http://185.130.5.231/login.php"
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = detector.analyze_url(url)
        
        print(f"Final Verdict: {result['verdict']} (Risk Score: {result['risk_score']:.2f})")
        print("\nKey Indicators:")
        
        if result['basic_features']['has_ip']:
            print("- Uses IP address directly")
        if result['basic_features']['suspicious_tld']:
            print("- Suspicious TLD")
        if not result['basic_features']['has_https']:
            print("- No HTTPS")
        if result['advanced_checks']['typosquatting']:
            print("- Possible typosquatting")
        if result['advanced_checks']['homograph_attack']:
            print("- Possible homograph attack")
        if result['security_checks']['whois_info'].get('suspicious_age'):
            print("- Very new domain")
        if result['threat_intelligence']['PhishTank'].get('in_database'):
            print("- Listed in PhishTank")

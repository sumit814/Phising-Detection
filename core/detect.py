#!/usr/bin/env python3
import argparse
import json
from core.analyzer import URLAnalyzer
from core.threat_intel import ThreatIntelligence
from core.model import PhishingModel
from dotenv import load_dotenv
import os

def main():
    # Load configuration
    load_dotenv()
    api_keys = {
        'phishtank': os.getenv('PHISHTANK_API_KEY'),
        'google_safe_browsing': os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'),
        'virustotal': os.getenv('VIRUSTOTAL_API_KEY')
    }
    
    # Initialize components
    analyzer = URLAnalyzer()
    threat_intel = ThreatIntelligence(api_keys)
    model = PhishingModel('models/phishing_model.pkl', 'models/tfidf_vectorizer.pkl')
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='Advanced Phishing URL Detector')
    parser.add_argument('--url', type=str, required=True, help='URL to analyze')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()
    
    # Run analysis
    analysis = analyzer.analyze(args.url)
    threat_info = threat_intel.check_url(args.url)
    ml_prediction = model.predict(analysis['basic'])
    
    # Calculate risk score (0-1)
    risk_score = self._calculate_risk_score(analysis, threat_info, ml_prediction)
    verdict = "malicious" if risk_score > 0.7 else "suspicious" if risk_score > 0.4 else "clean"
    
    # Prepare results
    results = {
        'url': args.url,
        'verdict': verdict,
        'risk_score': round(risk_score, 2),
        'analysis': analysis,
        'threat_intelligence': threat_info,
        'ml_prediction': ml_prediction
    }
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n🔍 Analysis for: {args.url}")
        print(f"🛡️ Verdict: {verdict.upper()} (Risk Score: {risk_score:.2f})")
        print("\n📊 Key Indicators:")
        for check, result in analysis['basic'].items():
            if result: print(f"- {check.replace('_', ' ')}")
        if threat_info['phishtank'].get('in_database'):
            print("- Listed in PhishTank database")

def _calculate_risk_score(analysis, threat_info, ml_prediction) -> float:
    """Calculate comprehensive risk score (0-1)"""
    score = 0.0
    
    # Heuristics (40% weight)
    heuristics = analysis['basic']
    if heuristics['has_ip']: score += 0.10
    if heuristics['suspicious_tld']: score += 0.08
    if not heuristics['has_https']: score += 0.07
    if heuristics['many_hyphens']: score += 0.05
    if heuristics['is_encoded']: score += 0.05
    if analysis['advanced']['typosquatting']: score += 0.05
    
    # Threat Intel (30% weight)
    if threat_info['phishtank'].get('in_database'): score += 0.15
    if threat_info['google_safe_browsing'].get('malicious'): score += 0.10
    if threat_info['virustotal'].get('malicious'): score += 0.05
    
    # ML Prediction (30% weight)
    if 'probability_phishing' in ml_prediction:
        score += ml_prediction['probability_phishing'] * 0.30
    
    return min(score, 1.0)

if __name__ == "__main__":
    main()

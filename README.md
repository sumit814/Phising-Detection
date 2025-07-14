# 🛡️ Advanced Phishing URL Detector

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![ML](https://img.shields.io/badge/machine%20learning-scikit--learn-orange)

A multi-layered phishing detection system combining heuristic analysis, threat intelligence feeds, and machine learning to identify malicious URLs with high accuracy.

## 🌟 Key Features

- **Heuristic Engine**
  - Typosquatting detection (Levenshtein distance)
  - Homograph attack detection
  - Suspicious TLD analysis (.tk, .ml, .ga)
  - URL structure analysis (hyphens, special chars)

- **Threat Intelligence**
  - PhishTank API integration
  - Google Safe Browsing
  - VirusTotal scanning
  - OpenPhish feed

- **Security Analysis**
  - SSL/TLS certificate validation
  - WHOIS domain age check
  - Redirect chain analysis

- **Machine Learning**
  - Pre-trained Random Forest classifier
  - 30+ extracted URL features
  - Real-time risk scoring

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Git
- API keys (free tiers available)

### 📋 API Keys Required

| Service | Free Tier | Key Location | Documentation |
|---------|-----------|-------------|---------------|
| PhishTank | Yes | `Config.PHISHTANK_API_KEY` | [API Docs](https://www.phishtank.com/api_info.php) |
| Google Safe Browsing | Yes (3k req/day) | `Config.GOOGLE_SAFE_BROWSING_API_KEY` | [API Docs](https://developers.google.com/safe-browsing) |
| VirusTotal | Yes (500 req/day) | `Config.VIRUSTOTAL_API_KEY` | [API Docs](https://developers.virustotal.com/) |

### 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/phishing-detector.git
   cd phishing-detector

# 🔍 Advanced Phishing URL Detector

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A multi-layered phishing detection system combining heuristic analysis, threat intelligence, and machine learning to identify malicious URLs with high accuracy.

## 🌟 Features

- **Heuristic Analysis**
  - Typosquatting detection (Levenshtein distance)
  - Homograph attack detection (IDNA/punycode)
  - Suspicious TLD detection
  - URL structure analysis

- **Threat Intelligence**
  - PhishTank integration
  - Google Safe Browsing API
  - VirusTotal scanning

- **Security Checks**
  - SSL/TLS certificate validation
  - WHOIS domain age analysis
  - Redirect chain analysis

- **Machine Learning**
  - Pre-trained Random Forest classifier
  - 30+ URL features extraction

## 📋 Prerequisites

### API Keys Required

| Service | Key Location | Free Tier | Documentation |
|---------|-------------|-----------|---------------|
| [PhishTank](https://www.phishtank.com/) | `Config.PHISHTANK_API_KEY` | ✅ Yes | [API Docs](https://www.phishtank.com/api_info.php) |
| [Google Safe Browsing](https://developers.google.com/safe-browsing) | `Config.GOOGLE_SAFE_BROWSING_API_KEY` | ✅ Yes (3k req/day) | [API Docs](https://developers.google.com/safe-browsing/v4) |
| [VirusTotal](https://www.virustotal.com/) | `Config.VIRUSTOTAL_API_KEY` | ✅ Yes (500 req/day) | [API Docs](https://developers.virustotal.com/reference) |

### Environment Variables

Create a `.env` file in project root:

```ini
PHISHTANK_API_KEY=your_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
VIRUSTOTAL_API_KEY=your_api_key_here


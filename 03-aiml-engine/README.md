# AEGISTRACE — AI/ML Threat Classification Engine (`03-aiml-engine`)

The **AEGISTRACE AIML Engine** provides real-time, explainable machine learning threat detection for URLs. It extracts 20 lexical, structural, and information-theoretic features and classifies URLs using a calibrated Random Forest classifier with graceful rule-based heuristic fallbacks.

---

## Architecture Overview

```
Raw URL Input
     ↓
[Feature Extraction (feature_extraction.py)]
     ├─ Lexical Metrics (length, depth, digit density)
     ├─ Security Tokens (@ symbol, double slash, redirect tokens)
     ├─ High-Abuse Indicators (suspicious TLDs, credential/auth lures)
     └─ Shannon Information Entropy (URL & domain randomness)
     ↓
[Preprocessed 20-Feature Vector]
     ↓
[Random Forest Classifier (models/phishing_model.joblib)]
     ├─ Calibrated Threat Probability P(Phishing)
     ├─ Explainable AI Risk Attribution (Top Risk Drivers)
     └─ Recommended Action (ALLOW, WARN, INVESTIGATE, BLOCK)
     ↓
Fused into [01-backend /api/analyze]
```

---

## 20-Feature Lexical & Structural Feature Matrix

| # | Feature Name | Type | Description |
|---|---|---|---|
| 1 | `url_length` | Integer | Total character count of full URL |
| 2 | `hostname_length` | Integer | Character count of domain/host |
| 3 | `subdomain_count` | Integer | Number of nested subdomain levels beyond domain + TLD |
| 4 | `digit_count` | Integer | Total count of numerical digits in URL |
| 5 | `digit_ratio` | Float | Ratio of digits to total URL length |
| 6 | `special_char_count` | Integer | Count of `-_?=&%@!~+$:;` |
| 7 | `suspicious_keyword_count` | Integer | Matches against 35+ credential, banking, and crypto lures |
| 8 | `is_https` | Binary (0/1) | Whether URL uses secure TLS transport |
| 9 | `is_ip_address` | Binary (0/1) | Whether host is a raw IPv4 or bracketed IPv6 address |
| 10 | `url_depth` | Integer | Number of non-empty path segments |
| 11 | `encoded_char_count` | Integer | Count of `%XX` hex-encoded bytes |
| 12 | `is_suspicious_tld` | Binary (0/1) | Matches against 30+ high-abuse TLDs (`.xyz`, `.top`, `.buzz`, etc.) |
| 13 | `has_redirect_token` | Binary (0/1) | Detects open redirect parameters (`dest=`, `url=`, `redirect=`) |
| 14 | `has_at_symbol` | Binary (0/1) | Authority spoofing delimiter `@` |
| 15 | `has_double_slash_path` | Binary (0/1) | Anomalous `//` path sequences |
| 16 | `hyphen_count_hostname` | Integer | Count of hyphens in domain name (typosquatting indicator) |
| 17 | `query_length` | Integer | Length of URL query parameters string |
| 18 | `path_length` | Integer | Length of URL path component |
| 19 | `entropy` | Float | Shannon information entropy of full URL (bits/symbol) |
| 20 | `domain_entropy` | Float | Shannon information entropy of hostname |

---

## Benchmark Dataset & Model Performance

- **Dataset Size**: 1,280 curated, verified benchmark URLs (`data/urls_dataset.csv`)
  - Safe / Legitimate URLs: Popular corporate, open-source, academic, and SaaS domains.
  - Suspicious URLs: Excessive subdomains, dynamic DNS, greyware, and affiliate redirects.
  - Phishing URLs: IP-hosted login lures, credential harvesting, typosquats, crypto airdrop scams.
- **Model**: `RandomForestClassifier` with balanced class weights, 120 estimators, max depth 10.
- **Evaluation Split**: 80% Stratified Training (1,024 samples) / 20% Testing (256 samples).

### Performance Metrics (`models/evaluation_report.json`)

| Metric | Score |
|---|---|
| **Accuracy** | **99.61%** |
| **Precision** | **100.00%** |
| **Recall** | **99.30%** |
| **F1 Score** | **99.65%** |
| **ROC-AUC** | **0.9997** |
| **5-Fold CV F1** | **98.85% (±0.008)** |

---

## Usage & API

### Python Inference

```python
from predict import predict_url

result = predict_url("http://192.168.1.100/login-paypal-verify.php?auth=true")
print(result["risk_score"])          # 0.95
print(result["classification"])        # HIGH_RISK
print(result["recommended_action"])    # BLOCK
print(result["explanation"])           # ['Host is a raw IP address...', ...]
```

### Running Tests

```powershell
# Run AIML unit tests
.\.venv\Scripts\python.exe -m pytest 03-aiml-engine/tests -v

# Run entire repository test suite
.\.venv\Scripts\python.exe -m pytest -v
```

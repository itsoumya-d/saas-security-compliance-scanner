# saas-security-compliance-scanner

Automated SaaS security posture scanner, OWASP API assessment, cryptographic audit engine, and SOC 2 / ISO 27001 compliance verification harness.

## Overview
Enterprise SaaS applications handling customer data require automated continuous security posture audits:
- **OWASP API Security Audit**: Validates API response headers, CORS misconfigurations (wildcard reflection), authorization enforcement, and rate-limiting headers.
- **Cryptographic & Key Rotation Audits**: Evaluates cryptographic key age against 90-day rotation policies, checks TLS protocol versions (>= TLS 1.2), and validates encryption-at-rest configurations.
- **Cloud Security & CIS Benchmark Checks**: Scans multi-cloud storage buckets (AWS S3, GCP Cloud Storage) and database instances for public access blocks and default encryption enforcement.
- **Compliance Framework Mapping**: Automatically maps findings to SOC 2 Trust Services Criteria (CC6.1, CC6.6, CC6.7) and ISO 27001 Annex A controls (A.10 Cryptography, A.12 Operations Security).

## Installation & Testing
```bash
pip install -r requirements.txt
pytest -v
```

# QFireNet — Backend

> AI-Powered Digital Trust & Cyber Risk Assessment Platform  
> Module 1: Website Analyzer

## Quick Start

### 1. Prerequisites
- Python 3.11+
- PostgreSQL 14+ running locally
- A free Groq API key → https://console.groq.com

### 2. Set up PostgreSQL

```sql
-- Run in psql:
CREATE DATABASE qfirenet;
```

### 3. Configure environment

```bash
cd qfirenet/backend
cp .env.example .env
# Edit .env and fill in DATABASE_URL and GROQ_API_KEY
```

### 4. Install dependencies

```bash
# Create a virtual environment (recommended)
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### 5. Run the server

```bash
# From the qfirenet/backend directory:
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- Swagger UI: http://localhost:8000/docs  
- Health check: http://localhost:8000/

### 6. Test the endpoint

```bash
curl -X POST http://localhost:8000/scan/website \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Architecture

```
POST /scan/website
        │
        ├── check_ssl()           → SSL cert validity, expiry, TLS version
        ├── check_whois()         → Domain age, registrar
        ├── check_phishing_heuristics() → URL structure analysis
        └── check_pqc_readiness() → Post-Quantum Crypto cipher check
                    │
                    ▼
        calculate_trust_score()   → Weighted 0–100 score
                    │
                    ▼
        generate_explanation()    → Groq LLM plain-English explanation
                    │
                    ▼
        ScanResult → PostgreSQL   → JSON response
```

## Scoring Weights

| Signal              | Weight | Rationale |
|---------------------|--------|-----------|
| Phishing Heuristics | 35%    | URL patterns are the most reliable indicator |
| SSL Validity        | 25%    | An expired cert is a hard failure |
| WHOIS / Domain Age  | 25%    | New domains = high phishing risk |
| PQC Readiness       | 15%    | Informational / future-risk only |

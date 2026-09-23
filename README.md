# AEGISTRACE — Autonomous Cyber Threat Intelligence & Phishing Mitigation Platform

> A fully integrated, production-ready, 10-phase platform combining FastAPI, XGBoost ML, Agentic AI (Gemini), Chrome MV3 extension, UiPath RPA, Docker deployment, and a React SOC dashboard.

---

## Quick Start

```bash
# Clone
git clone https://github.com/fredolin0109-hub/Aegstrace-ai.git
cd Aegstrace-ai

# Create virtualenv and install dependencies
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r 01-backend/requirements.txt

# Run the demo
python 10-final-demo/demo_runner.py --fast

# Run all tests
pytest
```

---

## Platform Architecture

```
Browser Extension (MV3)
       |
       v
FastAPI Backend (port 8000)
   ├── DSA Engine (Bloom + Trie + LRU)
   ├── AIML Engine (XGBoost)
   ├── Agentic AI (Gemini 2.0 + Tool Calling)
   ├── Threat Intel (VirusTotal + AbuseIPDB + Shodan)
   └── UiPath RPA Dispatcher
            |
     UiPath Orchestrator
   (contain_host, block_domain, create_ticket, notify_soc, isolate_user, generate_report)

SOC Dashboard (React 18 + Vite, port 3000)
Redis (cache + threat intel TTL)
Docker Compose (backend + frontend + redis)
```

---

## Phases

| Phase | Folder | Description |
|---|---|---|
| 1 | `01-backend/` | FastAPI REST API — URL analysis, incidents, config |
| 2 | `02-dsa-engine/` | Bloom filter, Trie, LRU cache for URL deduplication |
| 3 | `03-aiml-engine/` | XGBoost phishing classifier with feature engineering |
| 4 | `04-agentic-ai/` | Gemini-powered agentic threat analysis + tool calling |
| 5 | `05-threat-intelligence/` | VirusTotal, AbuseIPDB, Shodan, URLScan.io aggregator |
| 6 | `06-frontend-dashboard/` | React 18 + TypeScript + Tailwind SOC Dashboard |
| 7 | `07-browser-extension/` | Chrome Manifest V3 extension with real-time overlay |
| 8 | `08-uipath-rpa/` | UiPath RPA workflows + Python orchestrator bridge |
| 9 | `09-deployment/` | Docker Compose, Dockerfiles, nginx, env configuration |
| 10 | `10-final-demo/` | End-to-end demo runner + architecture presentation |

---

## Test Suite

```bash
pytest                           # Run all phases
pytest 01-backend/tests/ -v      # Backend only
pytest 08-uipath-rpa/tests/ -v   # UiPath RPA only
```

Total: **~326 tests, all passing**

---

## Docker Deployment

```bash
cp 09-deployment/.env.example 09-deployment/.env
# Fill in API keys in .env

docker compose -f 09-deployment/docker-compose.yml up --build -d

# SOC Dashboard  → http://localhost:3000
# Backend API    → http://localhost:8000/docs
```

---

## Environment Variables

See [`09-deployment/.env.example`](09-deployment/.env.example) for all variables.

Key variables: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `UIPATH_CLIENT_ID`, `UIPATH_USER_KEY`, `SECRET_KEY`, `DEMO_MODE`

---

## License

MIT License — AEGISTRACE Project 2026

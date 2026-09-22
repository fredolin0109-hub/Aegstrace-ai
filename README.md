# AEGISTRACE: AI-Powered Phishing Detection & Automated Response Platform

> **AEGISTRACE** is a real, functional, deployable cybersecurity platform combining Client-Side Browser Protection, Fast Data Structures & Algorithms (DSA), AI/ML Threat Classification, Autonomous Agentic AI Investigation, and UiPath RPA Automated Security Response.

---

## Architecture Overview

```
User visits Website
        ↓
[Chrome Extension (Manifest V3)]
        ↓ URL Extraction & Quick Heuristics
[FastAPI Backend (/api/analyze)]
        ↓
[02-dsa-engine] ── Fast Pattern Matching (Trie, HashMap, Domain Graph, Priority Queue)
        ↓
[03-aiml-engine] ─ Supervised ML Feature Extraction & Phishing Classification
        ↓ Threat Score & Confidence
[04-agentic-ai] ── Autonomous Investigation, Multi-source Verification & Decision Engine
        ↓ High Risk Escalation
[08-uipath-rpa] ── Automated Security Response (Ticketing, Host Containment, Admin Alert)
        ↓
[06-frontend-dashboard] ── Real-Time SOC Incident Monitoring, Live Auditing, and Metrics
```

---

## 10-Phase Implementation Roadmap

- [x] **PHASE 1**: Backend + Database (FastAPI, SQLAlchemy 2.0, Pydantic v2, SQLite/PostgreSQL, 9 REST APIs, Audit Trail)
- [x] **PHASE 2**: DSA Engine (Trie, HashMap, Threat Graph, Priority Queue, Searching & Sorting)
- [x] **PHASE 3**: AIML Engine (URL Feature Extraction, ML Model Training, Risk Prediction Pipeline)
- [ ] **PHASE 4**: Agentic AI (Tool-based Investigation, Evidence Trace, Automated Escalation)
- [ ] **PHASE 5**: Threat Intelligence (Multi-provider aggregator, Fallbacks, Caching)
- [ ] **PHASE 6**: Frontend Dashboard (React + TypeScript + Tailwind CSS SOC Dashboard)
- [ ] **PHASE 7**: Browser Extension (Chrome Manifest V3 Extension with Live Protection)
- [ ] **PHASE 8**: UiPath RPA (Controlled RPA Incident Containment & Ticketing Workflows)
- [ ] **PHASE 9**: Full Integration (End-to-end telemetry from Extension to RPA)
- [ ] **PHASE 10**: Testing & Deployment (E2E Test Suite, Docker, Demo Environments)

---

## Quick Start (Phase 1: Backend & Database)

### 1. Prerequisites
- Python 3.12+
- Node.js 18+ (for frontend phases)

### 2. Environment Setup
```powershell
# Create Python 3.12 virtual environment
py -3.12 -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r 01-backend/requirements.txt
```

### 3. Run the Backend API
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir 01-backend --host 127.0.0.1 --port 8000 --reload
```

Interactive API documentation will be available at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### 4. Run Automated Tests
```powershell
.\.venv\Scripts\python.exe -m pytest 01-backend/tests -v
```

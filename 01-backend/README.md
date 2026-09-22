# AEGISTRACE — Backend Service (`01-backend`)

The **AEGISTRACE Backend** is a high-performance REST API built with **FastAPI**, **SQLAlchemy 2.0**, and **Pydantic v2**. It manages threat scans, security incidents, agentic action traces, UiPath RPA workflow triggers, audit logs, and dashboard metrics.

---

## Directory Structure

```
01-backend/
├── app/
│   ├── config.py             # Pydantic Settings & environment variable configuration
│   ├── database.py           # SQLAlchemy engine, session maker, get_db dependency
│   ├── main.py               # FastAPI entry point, CORS middleware, lifespan events
│   ├── models/               # SQLAlchemy ORM models (SQLite/PostgreSQL compatible)
│   │   ├── agent_action.py   # Autonomous agent trace & tool invocation records
│   │   ├── audit_log.py      # Immutable security audit trail
│   │   ├── incident.py       # Security incident records & lifecycle
│   │   ├── threat_indicator.py # Specific threat markers (typosquatting, IP host, etc.)
│   │   ├── uipath_action.py  # RPA execution telemetry and status
│   │   └── url_scan.py       # Raw & normalized scan telemetry with risk scoring
│   ├── schemas/              # Pydantic v2 validation models
│   │   ├── agent.py          # /api/investigate request & response schemas
│   │   ├── dashboard.py      # /api/dashboard/stats metric schemas
│   │   ├── incident.py       # /api/incidents schemas & filters
│   │   ├── scan.py           # /api/analyze request & response schemas
│   │   └── uipath.py         # /api/uipath/trigger & status schemas
│   ├── routes/               # API Routers (mounted under /api)
│   │   ├── health.py         # GET /api/health
│   │   ├── analyze.py        # POST /api/analyze
│   │   ├── investigate.py    # POST /api/investigate
│   │   ├── incidents.py      # POST, GET, PATCH /api/incidents
│   │   ├── uipath.py         # POST /api/uipath/trigger, GET /api/uipath/status/{id}
│   │   └── dashboard.py      # GET /api/dashboard/stats
│   └── services/             # Core business logic & database transactions
│       ├── audit_service.py
│       ├── incident_service.py
│       ├── scan_service.py
│       ├── stats_service.py
│       └── uipath_service.py
├── tests/                    # Automated pytest test suite
│   ├── conftest.py           # In-memory SQLite & TestClient fixtures
│   ├── test_analyze.py
│   ├── test_dashboard.py
│   ├── test_dsa_integration.py
│   ├── test_health.py
│   ├── test_incidents.py
│   ├── test_investigate.py
│   └── test_uipath.py
├── Dockerfile                # Production container specification
├── requirements.txt          # Python package dependencies
└── README.md
```

---

## API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service root and status |
| `GET` | `/api/health` | Health check, DB connectivity, demo mode status |
| `POST` | `/api/analyze` | Ingest URL, extract heuristics & compute initial threat score |
| `POST` | `/api/investigate` | Multi-step agentic investigation & autonomous escalation |
| `POST` | `/api/incidents` | Create a security incident |
| `GET` | `/api/incidents` | List incidents with status/severity/search filters & sorting |
| `GET` | `/api/incidents/triage` | Triage active incidents using DSA Priority Queue (Max-Heap) |
| `GET` | `/api/incidents/{id}` | Detailed incident with RPA actions & threat indicators |
| `PATCH`| `/api/incidents/{id}` | Update incident status, severity, or assignment |
| `POST` | `/api/uipath/trigger` | Trigger an authorized UiPath RPA response |
| `GET` | `/api/uipath/status/{id}`| Poll status and payload of a UiPath RPA action |
| `GET` | `/api/dashboard/stats` | Aggregated SOC metrics, trends, and recent activity |

---

## How to Run Locally

### 1. Set Up Virtual Environment & Dependencies
```powershell
# From project root
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r 01-backend/requirements.txt
```

### 2. Start the Server
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir 01-backend --host 127.0.0.1 --port 8000 --reload
```

### 3. Run Automated Tests
```powershell
.\.venv\Scripts\python.exe -m pytest 01-backend/tests -v
```

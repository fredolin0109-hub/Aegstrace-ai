# 09-deployment — AEGISTRACE Docker & Deployment

## Overview

This module provides full containerised deployment for the AEGISTRACE platform using Docker Compose.

## Architecture

```
Host Port 3000 ──► [Frontend: nginx]  ──► /api/*  proxy ──► [Backend: FastAPI :8000]
                                                                     │
                                                             [Redis :6379] (cache/queue)
```

## Quick Start

```bash
# 1. Copy environment template and fill in your API keys
cp 09-deployment/.env.example 09-deployment/.env

# 2. Build and start all services
docker compose -f 09-deployment/docker-compose.yml up --build -d

# 3. Open the SOC Dashboard
# http://localhost:3000

# 4. Check service health
docker compose -f 09-deployment/docker-compose.yml ps
```

## Services

| Service | Image | Port | Description |
|---|---|---|---|
| `backend` | `aegistrace-backend:latest` | `8000` | FastAPI — all ML, DSA, threat intel engines |
| `frontend` | `aegistrace-frontend:latest` | `3000→80` | React dashboard served by nginx |
| `redis` | `redis:7.4-alpine` | `6379` | In-memory cache; threat intel TTL store |

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Service orchestration — build, ports, healthchecks, volumes |
| `Dockerfile.backend` | Python 3.12-slim image for FastAPI backend |
| `Dockerfile.frontend` | Multi-stage: Node 20 build → nginx:alpine serve |
| `nginx.conf` | SPA routing, gzip, API reverse proxy, static caching |
| `.env.example` | All required environment variables (copy to `.env`) |

## Environment Variables

See [`.env.example`](.env.example) for all variables. Key ones:

| Variable | Default | Description |
|---|---|---|
| `DEMO_MODE` | `true` | Use simulation for UiPath and ML stubs |
| `SECRET_KEY` | — | Strong random key for token signing |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API key |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `UIPATH_SIMULATION_MODE` | `true` | `false` = live UiPath Orchestrator |

## Individual Service Build

```bash
# Backend only
docker build -f 09-deployment/Dockerfile.backend -t aegistrace-backend:dev ./01-backend

# Frontend only
docker build -f 09-deployment/Dockerfile.frontend -t aegistrace-frontend:dev ./06-frontend-dashboard
```

## Healthchecks

All services have Docker HEALTHCHECK instructions:
- **Backend:** `GET /health` on port 8000
- **Frontend:** `GET /health` via nginx
- **Redis:** `redis-cli ping`

## Running Tests

```bash
.\.venv\Scripts\pytest 09-deployment\tests\ -v
```

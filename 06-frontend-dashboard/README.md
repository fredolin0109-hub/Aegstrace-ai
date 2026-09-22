# Phase 6 — Frontend SOC Operations Dashboard

The **AEGISTRACE Frontend Dashboard** is a mission-critical Security Operations Center (SOC) web application built to monitor, analyze, investigate, and remediate cyber phishing threats in real time. It pairs modern high-performance frontend tooling with dark-mode cyber defense aesthetics and deeply integrates with all previous phases: Phase 1 (FastAPI Backend), Phase 2 (DSA Engine), Phase 3 (AIML Engine), Phase 4 (Agentic AI), and Phase 5 (Threat Intelligence).

---

## 🚀 Key Technologies & Stack

- **Framework**: [React 18](https://react.dev/) + [TypeScript](https://www.typescriptlang.org/)
- **Bundler & Dev Server**: [Vite 5](https://vitejs.dev/) with Fast Refresh & Path Aliasing (`@/*`)
- **Styling**: [Tailwind CSS 3.4](https://tailwindcss.com/) with custom SOC palette (`slate-950`, cyber cyan, emerald, amber, rose)
- **Icons**: [lucide-react](https://lucide.dev/)
- **Routing**: [React Router DOM v6](https://reactrouter.com/)

---

## 🖥️ Core SOC Pages

| Page | Route | Description |
|---|---|---|
| **SOC Overview** | `/` | Real-time defense grid metrics, active incident counts, severity & status distribution bars, and live recent scan & incident activity feeds. |
| **URL Threat Analyzer** | `/analyze` | Interactive URL inspection terminal with cyber radar loading state, circular SVG threat score gauge, multi-engine breakdown (DSA Trie/Graph, XGBoost ML, Threat Intel), IOC indicator list, and autonomous agent investigation escalation. |
| **Incident Command Queue** | `/incidents` | Filterable and searchable incident triage queue with DSA Priority Queue (Max-Heap) and Stable MergeSort sorting strategies, pagination, and manual incident creation modal. |
| **Forensic Incident View** | `/incidents/:id` | Full forensic incident details view with 6-stage audit lifecycle timeline, evidence dossier, status modification, and interactive UiPath RPA response dispatcher (`CONTAIN_HOST`, `BLOCK_DOMAIN`, `CREATE_TICKET`, etc.) with live polling. |
| **Threat Intelligence Matrix** | `/threat-intel` | Multi-source reputation query (VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, Local Engine), live in-memory LRU TTL cache telemetry (hits, misses, hit ratio), and 1-click cache flush. |
| **System Telemetry & Settings** | `/settings` | Real-time backend ping diagnostics, database connectivity status, Demo mode indicator, environment variable overview, and master 10-phase roadmap tracking. |

---

## 🧩 Reusable SOC Components

- **`ThreatScoreGauge`**: Circular SVG animated radial gauge displaying normalized threat scores (0-100), classification color shifts (emerald safe, amber suspicious, rose high-risk), and ML confidence.
- **`AuditTimeline`**: Dynamic stepper representing the SOC incident progression: `DETECTED` ➔ `ANALYZED` ➔ `INVESTIGATED` ➔ `DECIDED` ➔ `UIPATH ACTION` ➔ `VERIFIED`, plus nested agent action trace logs and RPA execution details.
- **`StatCard`**: High-contrast cyber telemetry card with status icons, trend arrows, and glowing hover accents.
- **`SeverityBadge` & `StatusBadge`**: Glowing pill badges color-coded by incident severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`).
- **`EvidenceCard`**: Forensic finding card displaying ML explainability features, DNS WHOIS context, and graph cycle topologies with 1-click clipboard copying.
- **`ThreatIndicatorList`**: Expandable IOC accordion list displaying extracted threat indicators, signatures, and values.
- **`Sidebar` & `Topbar`**: Persistent SOC navigation with live backend API health heartbeat, UTC SOC operational clock, and fast action triggers.

---

## 🔌 API Client Service (`src/services/api.ts`)

The centralized API client communicates directly with the FastAPI backend at `http://127.0.0.1:8000`:
- `GET  /api/health` ➔ Real-time health and demo mode state
- `POST /api/analyze` ➔ Fast DSA + AIML + Threat Intel URL inspection
- `POST /api/investigate` ➔ Multi-step autonomous agent investigation
- `GET  /api/dashboard/stats` ➔ Aggregated SOC counts and activity feeds
- `GET  /api/incidents` ➔ Paginated incidents with status, severity, and DSA sorting
- `GET  /api/incidents/triage` ➔ Priority queue triaged incidents
- `GET  /api/incidents/{id}` ➔ Detailed incident metadata and RPA action history
- `PATCH /api/incidents/{id}` ➔ Status updates (e.g. `CONTAINED`, `RESOLVED`)
- `POST /api/incidents` ➔ Manual analyst incident creation
- `POST /api/uipath/trigger` ➔ Dispatches automated containment playbooks
- `GET  /api/uipath/status/{id}` ➔ Live status & progress polling for RPA workflows
- `GET  /api/threat-intel/lookup` ➔ Multi-provider reputation query
- `GET  /api/threat-intel/stats` ➔ LRU cache diagnostics and source availability
- `POST /api/threat-intel/clear-cache` ➔ Cache purge

---

## 🛠️ Development & Build

### Install Dependencies
```bash
cd 06-frontend-dashboard
npm install
```

### Run Local Development Server
```bash
npm run dev
```
The dashboard starts at `http://localhost:5173`.

### Production Build & Type Checking
```bash
npm run build
```
Generates an optimized, tree-shaken static bundle in `06-frontend-dashboard/dist/` with clean TypeScript verification (`tsc -b`).

# AEGISTRACE — Autonomous Agentic AI System (`04-agentic-ai`)

The **AEGISTRACE Agentic AI Engine** is an autonomous cybersecurity investigation and automated incident response system. Orchestrated by `AegisAgent`, it conducts evidence-grounded investigations of suspicious URLs across a strict 5-phase lifecycle: **DETECT → INVESTIGATE → DECIDE → ACT → VERIFY**.

---

## 5-Phase Agent Investigation Lifecycle

```
                    [ Target URL / Threat Indicator ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. DETECT (tools/analyze_url.py)                                            │
│    ├─ Fast Algorithmic Scanning via 02-dsa-engine (Trie, HashMap)           │
│    ├─ Supervised Machine Learning via 03-aiml-engine (Random Forest)        │
│    └─ Initial Threat Scoring & Baseline Evidence Generation                 │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. INVESTIGATE (Multi-tool Evidence Gathering)                              │
│    ├─ tools/threat_lookup.py  -> Local Threat HashMap & Parent Domain Tree  │
│    ├─ tools/domain_check.py   -> Shannon Entropy, TLD Abuse & Brand Spoofs  │
│    └─ tools/redirect_check.py -> ThreatGraph Topology & Cycle Detection     │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. DECIDE (decision_engine.py)                                              │
│    ├─ Low Risk (<0.35)   -> SAFE_PASS (ALLOW)                               │
│    ├─ Medium Risk (0.35-0.69) -> MONITOR (standard) or ESCALATE (deep)     │
│    └─ High Risk (>=0.70) -> TRIGGER_AUTOMATED_RESPONSE (BLOCK_AND_CONTAIN)  │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. ACT (Response & Containment Dispatch)                                    │
│    ├─ tools/create_incident.py -> Formal SOC Incident in Database           │
│    ├─ tools/trigger_uipath.py  -> Authorized UiPath RPA Workflows           │
│    └─ Logging / Gateways       -> Safe passage authorizer or SOC telemetry  │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. VERIFY (tools/verify_response.py)                                        │
│    ├─ UiPath RPA Job Execution Confirmation (SUCCESS / SIMULATED)           │
│    ├─ Network Containment & DNS Sinkhole Verification                       │
│    ├─ SOC Ticket Issuance Validation                                        │
│    └─ Immutable Action Trace Persistence (app/models/agent_action.py)       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Components

### 1. Modular Tool Registry (`04-agentic-ai/tools/`)

| Tool | File | Purpose |
|---|---|---|
| `analyze_url` | `tools/analyze_url.py` | Runs algorithmic (DSA) pattern matching and machine learning (AIML) baseline risk scoring. Supports existing `url_scan_id` linkage. |
| `threat_lookup` | `tools/threat_lookup.py` | Queries local $O(1)$ DSA hashmap with hierarchical parent domain fallback and database threat indicator cross-referencing. |
| `domain_check` | `tools/domain_check.py` | Measures Shannon information entropy, detects high-abuse TLDs, calculates nested subdomain depth, raw IP hosts, and brand impersonation. |
| `redirect_check` | `tools/redirect_check.py` | Analyzes HTTP redirect sequences using directed `ThreatGraph`, detects cycles/loops via DFS coloring, and identifies open redirect parameters. |
| `create_incident` | `tools/create_incident.py` | Creates official SOC incident records (`INC-YYYYMMDD-XXXX`) in the database with severity classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `trigger_uipath` | `tools/trigger_uipath.py` | Dispatches authorized UiPath RPA workflows (`CONTAIN_HOST`, `BLOCK_DOMAIN`, `CREATE_TICKET`, `NOTIFY_SOC`) with execution tracking. |
| `verify_response` | `tools/verify_response.py` | Verifies execution status, endpoint network isolation, DNS sinkhole activation, and incident ticket issuance. |

### 2. Auditable Action Trace Tracker (`action_trace.py`)

- **`ActionTraceItem`**: Represents an atomic step executed by the agent, capturing `action_type`, `tool_name`, `tool_input`, `tool_output`, `decision_rationale`, `status`, and UTC `timestamp`.
- **`ActionTrace`**: Maintains state across the 5 phases, deduplicating evidence, updating risk transitions, and persisting each step to the `agent_actions` database table.

### 3. Deterministic Decision Engine (`decision_engine.py`)

- **Enterprise Allowlist Overrides**: Zero false-positive pass-through for verified enterprise domains (`SAFE_PASS`).
- **High-Risk & Evasive Loop Auto-Containment**: Triggers automated RPA isolation (`CONTAIN_HOST`) for verified phishing lures, known malicious domains, or redirect loops.
- **Deep Investigation Escalation**: Upgrades medium-risk threats to formal SOC review when investigated under `depth="deep"`.
- **Administrative Force Escalation**: Enables immediate SOC escalation on operational demand.

### 4. Autonomous Agent Orchestrator (`agent.py`)

- **`AegisAgent`**: Unifies all tools, decision matrices, and action trace logging into a cohesive, production-grade interface. Works both integrated within FastAPI routes and standalone in CLI/offline environments.

---

## Backend Integration

The agent is integrated into `01-backend/app/routes/investigate.py` (`POST /api/investigate`).

```python
from agent import AegisAgent

agent = AegisAgent(db=db)
trace = agent.investigate(
    url=payload.url,
    url_scan_id=payload.url_scan_id,
    depth=payload.depth,
    force_escalate=payload.force_escalate,
)
```

Every investigation automatically stores its step-by-step trace in the `agent_actions` table, linked to the `url_scans` and `incidents` records for auditing.

---

## Running Tests

```powershell
# Run Agentic AI unit tests
.\.venv\Scripts\python.exe -m pytest 04-agentic-ai/tests -v

# Run entire repository test suite (01-backend, 02-dsa-engine, 03-aiml-engine, 04-agentic-ai)
.\.venv\Scripts\python.exe -m pytest -v
```

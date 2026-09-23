# 08-uipath-rpa — AEGISTRACE UiPath RPA Module

## Overview

This module provides the **UiPath Robotic Process Automation** integration layer for AEGISTRACE. When a phishing or cyber-threat incident is confirmed, the Python dispatcher bridges the AEGISTRACE backend to UiPath Cloud Orchestrator, triggering automated remediation workflows.

## Architecture

```
AEGISTRACE Backend  ──►  dispatcher.py  ──►  UiPath Orchestrator  ──►  Workflow XAML
   (FastAPI)               (Python CLI)         (REST API / Sim)       (Main.xaml)
```

## Supported Actions

| Action | Workflow | Description |
|---|---|---|
| `contain_host` | `ContainHost.xaml` | Isolate a compromised host via firewall/EDR |
| `block_domain` | `BlockDomain.xaml` | Block malicious domain in DNS/proxy |
| `create_ticket` | `CreateTicket.xaml` | Open ServiceNow/Jira incident ticket |
| `notify_soc` | `NotifySOC.xaml` | Send alert email/Teams message to SOC team |
| `isolate_user` | `IsolateUser.xaml` | Suspend AD/Azure AD account |
| `generate_report` | `GenerateReport.xaml` | Produce PDF forensic report |

## Project Structure

```
08-uipath-rpa/
├── project.json          # UiPath project metadata
├── Main.xaml             # Master orchestrator (Switch routing)
├── dispatcher.py         # Python CLI bridge to UiPath Orchestrator
├── workflows/
│   ├── ContainHost.xaml
│   ├── BlockDomain.xaml
│   ├── CreateTicket.xaml
│   ├── NotifySOC.xaml
│   ├── IsolateUser.xaml
│   └── GenerateReport.xaml
├── sample-data/          # Example trigger payloads (JSON)
└── tests/
    └── test_dispatcher.py
```

## dispatcher.py Usage

### Simulation Mode (no UiPath required)

```bash
# Dry-run all 6 actions
python 08-uipath-rpa/dispatcher.py --test-all

# Dispatch a single action in simulation
python 08-uipath-rpa/dispatcher.py \
    --action contain_host \
    --incident-id 1234 \
    --params '{"hostname": "LAPTOP-001", "ip": "192.168.1.50"}'
```

### Live UiPath Orchestrator Mode

Set the following environment variables:

```bash
UIPATH_ORCHESTRATOR_URL=https://cloud.uipath.com
UIPATH_TENANT_NAME=your-tenant
UIPATH_CLIENT_ID=your-client-id
UIPATH_USER_KEY=your-user-key
UIPATH_PROCESS_NAME=AEGISTRACE_Remediation
UIPATH_SIMULATION_MODE=false
```

Then run without `--test-all`:

```bash
python 08-uipath-rpa/dispatcher.py \
    --action block_domain \
    --incident-id 5678 \
    --params '{"domain": "evil-phish.com"}'
```

## Running Tests

```bash
# From project root
.\.venv\Scripts\pytest 08-uipath-rpa\tests\ -v
```

## UiPath Integration

Import the project into **UiPath Studio** by opening `project.json`. The `Main.xaml` workflow reads the `ActionType` input argument and routes to the appropriate sub-workflow via a Switch activity.

| Argument | Direction | Type | Description |
|---|---|---|---|
| `IncidentId` | In | Int32 | AEGISTRACE incident identifier |
| `ActionType` | In | String | One of the 6 supported actions |
| `Parameters` | In | String | JSON-encoded action parameters |
| `ExecutionId` | Out | String | UiPath job execution ID |
| `Status` | Out | String | `Completed` / `Failed` |
| `ResultMessage` | Out | String | Human-readable outcome |

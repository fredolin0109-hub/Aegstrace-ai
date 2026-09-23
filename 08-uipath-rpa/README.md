# 08-uipath-rpa — AEGISTRACE UiPath RPA & Automated Email Alert Module

## Overview

This module provides the **UiPath Robotic Process Automation** and **Automated Email Alerting** integration layer for AEGISTRACE. When a high-risk or suspicious cyber-threat incident is analyzed, the system bridges the AEGISTRACE backend to UiPath Studio / Cloud Orchestrator, executing automated remediation workflows and delivering priority security emails.

## Architecture

```
[Inbound URL Telemetry]
         │
         ▼
[AIML + DSA Engines + Agentic AI]
         │
         ▼
[Risk Score Tiering (LOW / MEDIUM / HIGH)]
         │
 ┌───────┴────────────────────────┐
 │ HIGH RISK (70-100)             │ MEDIUM RISK (30-69)       │ LOW RISK (0-29)
 ▼                                ▼                           ▼
[UiPath RPA Dispatcher]          [Incident Record Created]   [Scan Recorded Only]
 ├── AEGISTRACE_RiskAlert.xaml    └── Optional Email Notice   └── No Escalation
 ├── Priority HTML Email Alert
 └── SOC Dashboard + Audit Log
```

---

## Supported Workflows & Playbooks

| Action / Workflow | File | Description |
|---|---|---|
| `risk_alert` | `AEGISTRACE_RiskAlert.xaml` | Evaluates risk tiers (HIGH/MED/LOW), dispatches security email, triggers containment |
| `contain_host` | `ContainHost.xaml` | Network adapter isolation and host containment via EDR / PowerShell |
| `block_domain` | `BlockDomain.xaml` | Perimeter firewall ACL and DNS sinkhole blacklisting |
| `create_ticket` | `CreateTicket.xaml` | Enterprise ServiceNow / Jira P1/P2 SOC incident record |
| `notify_soc` | `NotifySOC.xaml` | Real-time Slack, Teams, and PagerDuty escalation alert |
| `isolate_user` | `IsolateUser.xaml` | Credential revocation, active session kill, forced password reset |
| `generate_report` | `GenerateReport.xaml` | Forensic evidence compilation into PDF and structured dossier |

---

## Project Structure

```
08-uipath-rpa/
├── project.json          # UiPath Studio project definition & metadata
├── Main.xaml             # Master orchestrator (Switch routing for all 7 actions)
├── dispatcher.py         # Python CLI bridge to UiPath Orchestrator / local simulation
├── workflows/
│   ├── AEGISTRACE_RiskAlert.xaml  # Master Risk Alert & Email Automation workflow
│   ├── ContainHost.xaml
│   ├── BlockDomain.xaml
│   ├── CreateTicket.xaml
│   ├── NotifySOC.xaml
│   ├── IsolateUser.xaml
│   └── GenerateReport.xaml
├── email-templates/
│   ├── high-risk.html    # Red cybersecurity alert template for HIGH risk
│   ├── medium-risk.html  # Amber security notice template for MEDIUM risk
│   └── README.md
├── integration/
│   ├── api-spec.md       # REST API contract for /api/risk-alert & /api/uipath/callback
│   └── payload-examples.json # Sample trigger payloads
├── sample-data/          # Example trigger payloads (JSON)
└── tests/
    ├── test_dispatcher.py          # 73 unit tests for Python dispatcher
    └── test_risk_alert_workflow.py # 8 tests validating XAML arguments & templates
```

---

## UiPath Workflow Arguments (`AEGISTRACE_RiskAlert.xaml`)

| Argument | Direction | Type | Description |
|---|---|---|---|
| `in_IncidentId` | In | String | Incident identifier (e.g. `INC-001` or `INC-20260923-9F31`) |
| `in_URL` | In | String | Suspicious / malicious URL target |
| `in_RiskScore` | In | Int32 | Composite risk score (0–100) |
| `in_RiskLevel` | In | String | `HIGH`, `MEDIUM`, or `LOW` |
| `in_Classification` | In | String | E.g. `HIGH_RISK`, `SUSPICIOUS`, `SAFE` |
| `in_Reasons` | In | String | Detected threat indicators / rationale |
| `in_Timestamp` | In | String | UTC detection timestamp |
| `in_RecipientEmail` | In | String | Recipient address from `ALERT_EMAIL` config |
| `out_Status` | Out | String | `COMPLETED`, `SKIPPED`, or `FAILED` |
| `out_EmailStatus` | Out | String | `SENT`, `QUEUED`, `SKIPPED`, or `FAILED` |
| `out_Message` | Out | String | Execution summary message |
| `out_ExecutionId` | Out | String | Unique execution task ID (e.g. `UIPATH-ALERT-...`) |

---

## Email Automation Configuration

The email integration does **not** hard-code any credentials. All settings are configurable in `.env`:

```bash
# Recipient address (SOC Admin / On-Call Engineer)
ALERT_EMAIL=security-admin@example.com

# Safe test mode: logs emails without sending real network traffic
EMAIL_TEST_MODE=true

# Enable/disable medium-risk alert notifications (HIGH is always active)
MEDIUM_RISK_EMAIL_ENABLED=false

# Production SMTP settings (used when EMAIL_TEST_MODE=false)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-smtp-user
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=aegistrace-alerts@example.com
SMTP_USE_TLS=true
```

---

## API Endpoints

### 1. Ingest Risk Alert
```bash
POST /api/risk-alert
Content-Type: application/json

{
  "url": "http://secure-login-paypal.phish-attack.xyz/verify?token=abc123",
  "risk_score": 94,
  "classification": "HIGH_RISK",
  "reasons": ["Suspicious URL structure", "Known threat indicator"],
  "incident_id": "INC-001"
}
```

### 2. UiPath Robot Callback
```bash
POST /api/uipath/callback
Content-Type: application/json

{
  "incident_id": "INC-001",
  "execution_id": "UIPATH-6D9B3FE7A8",
  "status": "COMPLETED",
  "email_status": "SENT",
  "timestamp": "2026-09-23T11:43:00Z"
}
```

### 3. Safe Automation Retry
```bash
POST /api/uipath/retry
Content-Type: application/json

{
  "incident_id": "INC-001",
  "retry_type": "ALL"
}
```

---

## UiPath Studio Direct Access

A complete, synchronized copy of this project is maintained in your local UiPath directory:
```
C:\Users\htmlv\OneDrive\Documents\UiPath\aegistraceai\
```
To open in UiPath Studio:
1. Launch **UiPath Studio**.
2. Select **Open a Local Project**.
3. Browse to `C:\Users\htmlv\OneDrive\Documents\UiPath\aegistraceai\project.json`.
4. Open and run `Main.xaml` or `workflows/AEGISTRACE_RiskAlert.xaml`.

---

## Running Automated Tests

```bash
# Test UiPath dispatcher CLI across all actions
.\.venv\Scripts\pytest 08-uipath-rpa/tests/test_dispatcher.py -v

# Test XAML arguments and email templates
.\.venv\Scripts\pytest 08-uipath-rpa/tests/test_risk_alert_workflow.py -v

# Test backend API endpoints
.\.venv\Scripts\pytest 01-backend/tests/test_risk_alert.py -v
```

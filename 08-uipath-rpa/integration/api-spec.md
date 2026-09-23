# AEGISTRACE UiPath RPA & Risk Alert API Specification

## 1. Risk Alert Intake Endpoint

**Endpoint:** `POST /api/risk-alert`  
**Description:** Ingests high-risk or suspicious URL telemetry from the browser extension, agentic AI, or URL analyzer. Automatically categorizes risk levels, logs or updates incidents, and initiates UiPath RPA automation & email alerting according to policy.

### Request Headers
- `Content-Type: application/json`

### Request Body
```json
{
  "url": "http://secure-login-paypal.phish-attack.xyz/verify?token=abc123",
  "risk_score": 94,
  "classification": "HIGH_RISK",
  "reasons": [
    "Deceptive top-level domain (.xyz)",
    "PayPal credential harvest pattern detected",
    "Known threat indicator"
  ],
  "incident_id": "INC-001"
}
```

### Response (200 OK)
```json
{
  "success": true,
  "risk_level": "HIGH",
  "incident_id": "INC-001",
  "uipath_status": "TRIGGERED",
  "email_status": "TEST_MODE_LOGGED",
  "execution_id": "EXEC-UIPATH-8B970A82",
  "message": "High-risk incident processed; UiPath workflow triggered and security alert email queued."
}
```

---

## 2. UiPath Execution Callback Endpoint

**Endpoint:** `POST /api/uipath/callback`  
**Description:** Webhook endpoint invoked by UiPath robots or orchestrator upon workflow completion. Updates incident status, records immutable audit trails, and logs final delivery statuses.

### Request Body
```json
{
  "incident_id": "INC-001",
  "execution_id": "EXEC-UIPATH-8B970A82",
  "status": "COMPLETED",
  "email_status": "SENT",
  "timestamp": "2026-09-23T10:30:00Z",
  "details": {
    "workflow": "AEGISTRACE_RiskAlert",
    "recipient": "security-admin@example.com",
    "action_taken": "EMAIL_DISPATCHED_AND_LOGGED"
  }
}
```

### Response (200 OK)
```json
{
  "success": true,
  "incident_id": "INC-001",
  "execution_id": "EXEC-UIPATH-8B970A82",
  "updated_status": "COMPLETED",
  "audit_log_id": 42
}
```

---

## 3. Automation Retry Endpoint

**Endpoint:** `POST /api/uipath/retry`  
**Description:** Idempotent retry mechanism for failed or unconfirmed UiPath or email dispatches.

### Request Body
```json
{
  "incident_id": "INC-001",
  "retry_type": "ALL"
}
```

### Response (200 OK)
```json
{
  "success": true,
  "incident_id": "INC-001",
  "uipath_status": "TRIGGERED",
  "email_status": "TEST_MODE_LOGGED",
  "execution_id": "EXEC-UIPATH-9A1F2C45"
}
```

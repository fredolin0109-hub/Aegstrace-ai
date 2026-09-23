# AEGISTRACE Automated Email Templates

This directory houses the HTML templates used for risk-driven email alerts triggered by UiPath RPA and the AEGISTRACE backend notification service.

## Templates

| Template | Subject Convention | Trigger Condition |
|---|---|---|
| `high-risk.html` | `[AEGISTRACE] HIGH-RISK Security Alert — {{incident_id}}` | Risk Score >= 70 (`HIGH`) |
| `medium-risk.html` | `[AEGISTRACE] Security Review Required — {{incident_id}}` | Risk Score 30–69 (`MEDIUM`, if enabled) |

## Supported Placeholders

Templates use standard double-brace interpolation tokens:

- `{{incident_id}}`: Incident identifier (e.g., `INC-20260923-9F31` or custom `INC-001`)
- `{{url}}`: The suspicious or high-risk URL under investigation
- `{{risk_score}}`: Numerical risk score (0–100)
- `{{classification}}`: Security classification (e.g. `HIGH_RISK`, `SUSPICIOUS`)
- `{{risk_level}}`: Qualitative risk tier (`HIGH`, `MEDIUM`, `LOW`)
- `{{reasons}}`: HTML formatted list items `<li>...</li>` representing detected indicators
- `{{timestamp}}`: UTC ISO timestamp or human-readable localized time

## Security & Privacy Guidelines

- **Never** include passwords, tokens, cookies, or authorization headers in alert bodies.
- Recipients are dynamically populated from `ALERT_EMAIL` in the environment configuration, **never** hard-coded.
- In `EMAIL_TEST_MODE=true` (default), emails are written to the audit log and mock logger rather than traversing external SMTP networks.

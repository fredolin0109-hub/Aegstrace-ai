# Phase 7 — AEGISTRACE Browser Extension (Manifest V3)

The **AEGISTRACE Browser Extension** is an autonomous real-time client-side cybersecurity shield built using Google Chrome's modern **Manifest V3** standard. It protects users as they browse the web by:
1. **Automatically capturing and inspecting destination URLs** — zero manual inputs required.
2. **Dispatching automated security email alerts and UiPath RPA workflows** when high-risk phishing or credential-harvesting threats are encountered.
3. **Triggering instant defensive warning popups** — including desktop notification popups, on-page modal overlays, dynamic badge percentages, and full SOC detail views.

---

## 🛡️ Autonomous Threat Defense Architecture

```
User Navigates Webpage (No Input Needed)
                 │
                 ▼
[Background Service Worker (MV3)]
  ├── Automatically captures active tab.url
  ├── Calls FastAPI Backend (http://localhost:8000/api/analyze)
  └── Evaluates Risk Tier (LOW / MEDIUM / HIGH)
                 │
  ┌──────────────┴───────────────────────────┐
  │ High-Risk Threat Detected (>=70%)        │ Low / Safe Target
  ▼                                          ▼
[Automated Incident Response Pipeline]    [Badge: 'OK' #10b981]
  ├── POST /api/risk-alert
  │    ├── Incident Ticket Created (INC-XXXX)
  │    ├── UiPath RPA Workflow Dispatched (AEGISTRACE_RiskAlert)
  │    └── Security Email Dispatched to SOC Administration
  │
  ├── 🚨 Desktop Notification Popup (chrome.notifications.create)
  ├── 🛑 In-Page Intercept Overlay Modal (content.js & banner.css)
  ├── 🔴 Extension Badge Status: '94%' (#f43f5e)
  └── 📊 Detail Popup Card: Email Dispatched & Incident ID
```

---

## 🚀 How to Install & Run the Extension in Chrome

1. Open Google Chrome (or any Chromium browser such as Edge, Brave, Opera).
2. Navigate to: `chrome://extensions/`
3. In the top-right corner, toggle on **"Developer mode"**.
4. Click the **"Load unpacked"** button in the top-left toolbar.
5. In the file picker dialog, select the extension folder:
   ```
   C:\Users\htmlv\OneDrive\Desktop\aegistrace ai\07-browser-extension
   ```
6. The **AEGISTRACE Phishing Shield** extension icon will appear in your Chrome toolbar. Pin it for quick access!

---

## 🔍 How to Test Without Giving Any Inputs

1. **Ensure the AEGISTRACE backend is running:**
   ```bash
   # From project root
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. **Navigate to any test website in Chrome:**
   - Normal website (e.g. `https://github.com`):
     - The extension automatically reads the URL.
     - Badge updates to **`OK`** (green).
     - Popup shows threat score ~10% and "SAFE".
   - Test phishing / high-risk URL pattern (e.g. `http://secure-login-paypal.phish-attack.xyz`):
     - The extension automatically intercepts the URL.
     - **Notification Popup:** A system notification pops up warning of high risk.
     - **Email Sent:** Background worker automatically calls `POST /api/risk-alert` &rarr; dispatches security alert email to `ALERT_EMAIL`!
     - **On-Page Warning:** A full-screen security banner intercepts the tab, confirming incident creation and email dispatch.
     - **Badge:** Changes to red with risk percentage (e.g. **`94%`**).
3. **Click the Extension Icon in the Chrome Toolbar:**
   - The popup opens and automatically displays the current URL analysis.
   - Shows the **AUTOMATED INCIDENT ALERT** card:
     - `Email Dispatch: ✓ SENT (SOC Admin)`
     - `UiPath RPA: ✓ TRIGGERED (AEGISTRACE_RiskAlert)`
     - `Incident ID: INC-XXXX`
   - You can also click **"Send Alert Email"** to trigger manual test alerts, or **"Open SOC Security Dashboard"** to jump directly to `http://localhost:3000/incidents`.

---

## 📁 Project Structure

```
07-browser-extension/
├── manifest.json                  # Manifest V3 configuration & permissions
├── generate_icons.py              # Pure Python PNG icon generator (16, 32, 48, 128)
├── icons/                         # Extension icons in standard dimensions
│   ├── icon-16.png
│   ├── icon-32.png
│   ├── icon-48.png
│   └── icon-128.png
├── src/
│   ├── background/
│   │   └── service-worker.js      # Auto URL reader, auto-email trigger & notification popup
│   ├── content/
│   │   ├── banner.css             # High-impact defensive intercept styling
│   │   └── content.js             # Defensive DOM warning injector with email status badge
│   ├── popup/
│   │   ├── popup.html             # Cyber SOC popup markup with email & RPA cards
│   │   ├── popup.css              # Dark palette styling (#030712, cyan, rose)
│   │   └── popup.js               # Auto-read URL, gauge animation & alert controller
│   └── services/
│       └── api.js                 # API service with analyzeUrl, sendRiskAlert, fallback
└── tests/
    ├── test_extension_manifest.py    # 5 manifest and integrity tests
    └── test_extension_automation.py  # 12 automation, URL capture & email alert tests
```

---

## 🧪 Running Automated Tests

Run the full extension test suite via pytest:
```bash
.\.venv\Scripts\pytest 07-browser-extension/tests/ -v
```
All 17 tests validate Manifest V3 structure, automatic tab reading permissions, automated email triggers, notification creation, and popup controls.

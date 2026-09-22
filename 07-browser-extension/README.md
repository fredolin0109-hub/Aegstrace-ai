# Phase 7 — AEGISTRACE Browser Extension (Manifest V3)

The **AEGISTRACE Browser Extension** is a real-time, client-side cybersecurity shield built using Google Chrome's modern **Manifest V3** standard. It protects users as they browse the web by inspecting destination URLs, evaluating live risk scores via the FastAPI backend, dynamically updating the action badge, and rendering in-page warning overlays on confirmed phishing domains.

---

## 🛡️ Architecture & Components

```
┌─────────────────────────────────────────────────────────────┐
│                       Chrome / Edge                         │
│                                                             │
│   ┌─────────────────────┐       ┌───────────────────────┐   │
│   │   Content Script    │       │     Popup UI          │   │
│   │ (Warning Overlay &  │◄──────┤ (SOC Dark Theme, SVG  │   │
│   │   Banner Intercept) │       │  Threat Gauge, IOCs)  │   │
│   └──────────┬──────────┘       └───────────┬───────────┘   │
│              │                              │               │
│              ▼                              ▼               │
│   ┌─────────────────────────────────────────────────────┐   │
│   │       Background Service Worker (MV3)               │   │
│   │  • chrome.tabs.onUpdated / onActivated              │   │
│   │  • Persistent TTL Caching (chrome.storage.local)    │   │
│   │  • Dynamic Action Badge (#10b981 / #f59e0b / #f43f5e│   │
│   └──────────────────────────┬──────────────────────────┘   │
└──────────────────────────────┼──────────────────────────────┘
                               │ HTTP / JSON
                               ▼
               ┌───────────────────────────────┐
               │    AEGISTRACE FastAPI API     │
               │     http://127.0.0.1:8000     │
               │   • POST /api/analyze         │
               │   • POST /api/investigate     │
               │   • POST /api/uipath/trigger  │
               └───────────────────────────────┘
```

---

## 📁 Directory Structure

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
│   │   └── service-worker.js      # Background navigation interceptor & badge controller
│   ├── content/
│   │   ├── banner.css             # High-impact defensive intercept styling
│   │   └── content.js             # Defensive DOM warning injector
│   ├── popup/
│   │   ├── popup.html             # Cyber SOC popup markup
│   │   ├── popup.css              # Dark palette styling (#030712, cyan, rose)
│   │   └── popup.js               # Reactive gauge animation & action dispatcher
│   └── services/
│       └── api.js                 # Backend client with local heuristic fallback
└── tests/
    └── test_extension_manifest.py # Automated pytest test suite
```

---

## ⚡ Loading the Extension in Chrome / Brave / Edge

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** via the toggle switch in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the folder: `c:\Users\htmlv\OneDrive\Desktop\aegistrace ai\07-browser-extension`.
5. The **AEGISTRACE Phishing Shield** icon will appear in your browser extension toolbar!

---

## 🧪 Testing

Run the automated test suite verifying manifest validity, icon formats, and service worker bindings:

```bash
.\.venv\Scripts\pytest 07-browser-extension/tests -v
```

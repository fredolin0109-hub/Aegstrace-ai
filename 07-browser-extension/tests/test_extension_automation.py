"""
Phase 07 — Browser Extension Automation & Automated Email Alert Tests
Validates:
- Automatic active tab URL detection (no manual inputs)
- Automated risk alert & email dispatch integration
- On-page warning intercept popup & desktop notification integration
- Manifest V3 notification permission and security boundaries
"""
import json
from pathlib import Path
import pytest

EXT_DIR = Path(__file__).resolve().parents[1]


class TestExtensionManifestAndPermissions:
    @pytest.fixture(scope="class")
    def manifest(self):
        manifest_file = EXT_DIR / "manifest.json"
        assert manifest_file.exists(), "manifest.json missing"
        with open(manifest_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_notifications_permission_present(self, manifest):
        perms = manifest.get("permissions", [])
        assert "notifications" in perms, "Manifest must declare 'notifications' permission for auto-popup alerts"

    def test_tabs_and_active_tab_permissions_for_automatic_url_reading(self, manifest):
        perms = manifest.get("permissions", [])
        assert "tabs" in perms, "Manifest requires 'tabs' permission to read tab.url automatically"
        assert "activeTab" in perms, "Manifest requires 'activeTab' permission"

    def test_backend_host_permissions_configured(self, manifest):
        host_perms = manifest.get("host_permissions", [])
        assert any("8000" in p for p in host_perms), "Host permissions must allow backend API access on 8000"


class TestServiceWorkerAutomation:
    @pytest.fixture(scope="class")
    def sw_content(self):
        sw_file = EXT_DIR / "src" / "background" / "service-worker.js"
        assert sw_file.exists()
        return sw_file.read_text(encoding="utf-8")

    def test_automatic_url_intake_handlers_present(self, sw_content):
        assert "chrome.tabs.onUpdated.addListener" in sw_content
        assert "chrome.tabs.onActivated.addListener" in sw_content
        assert "inspectTab" in sw_content

    def test_auto_email_alert_dispatch_for_high_risk(self, sw_content):
        assert "api.sendRiskAlert" in sw_content, "Service worker must call api.sendRiskAlert for high-risk URLs"
        assert "alertKey" in sw_content or "alert_sent" in sw_content, "Service worker must de-duplicate alerts"

    def test_desktop_notification_popup_created(self, sw_content):
        assert "chrome.notifications.create" in sw_content, "Service worker must call chrome.notifications.create"
        assert "AEGISTRACE: Threat Detected" in sw_content

    def test_on_message_handles_send_risk_alert(self, sw_content):
        assert "SEND_RISK_ALERT" in sw_content


class TestContentScriptOverlay:
    @pytest.fixture(scope="class")
    def content_js(self):
        f = EXT_DIR / "src" / "content" / "content.js"
        assert f.exists()
        return f.read_text(encoding="utf-8")

    def test_content_script_handles_high_risk_message(self, content_js):
        assert "AEGIS_HIGH_RISK_WARNING" in content_js
        assert "showThreatWarning" in content_js

    def test_content_script_renders_email_and_rpa_status(self, content_js):
        assert "AUTOMATED DEFENSE" in content_js
        assert "Email Notification" in content_js
        assert "UiPath RPA Workflow" in content_js


class TestPopupUiAndAutomation:
    @pytest.fixture(scope="class")
    def popup_html(self):
        f = EXT_DIR / "src" / "popup" / "popup.html"
        assert f.exists()
        return f.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def popup_js(self):
        f = EXT_DIR / "src" / "popup" / "popup.js"
        assert f.exists()
        return f.read_text(encoding="utf-8")

    def test_popup_html_has_automated_incident_alert_card(self, popup_html):
        assert "risk-alert-box" in popup_html
        assert "email-status-text" in popup_html
        assert "uipath-status-text" in popup_html
        assert "incident-id-text" in popup_html
        assert "btn-send-alert" in popup_html

    def test_popup_js_reads_url_automatically_without_input(self, popup_js):
        assert "chrome.tabs.query" in popup_js
        assert "currentUrl = tab.url" in popup_js
        assert "GET_ACTIVE_VERDICT" in popup_js

    def test_popup_js_handles_manual_alert_and_status(self, popup_js):
        assert "btnSendAlert" in popup_js
        assert "api.sendRiskAlert" in popup_js
        assert "ALERT DELIVERED" in popup_js

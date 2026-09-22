"""
Tests for Phase 7: Browser Extension (Manifest V3, Icons, Files, and Schemas)
"""
import json
import struct
from pathlib import Path
import pytest

EXT_DIR = Path(__file__).resolve().parents[1]


def test_manifest_structure():
    """Verify Manifest V3 validity, required fields, and safe permissions."""
    manifest_file = EXT_DIR / "manifest.json"
    assert manifest_file.exists(), "manifest.json must exist in extension root"

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest.get("manifest_version") == 3, "Extension must use Manifest V3"
    assert manifest.get("name") == "AEGISTRACE Phishing Shield"
    assert manifest.get("version") == "1.0.0"

    # Action / Popup
    action = manifest.get("action", {})
    assert "default_popup" in action
    popup_path = EXT_DIR / action["default_popup"]
    assert popup_path.exists(), f"Popup HTML file not found: {popup_path}"

    # Background service worker
    background = manifest.get("background", {})
    assert "service_worker" in background
    sw_path = EXT_DIR / background["service_worker"]
    assert sw_path.exists(), f"Service worker not found: {sw_path}"

    # Permissions
    perms = manifest.get("permissions", [])
    assert "activeTab" in perms
    assert "tabs" in perms
    assert "storage" in perms

    # Content scripts
    content_scripts = manifest.get("content_scripts", [])
    assert len(content_scripts) > 0
    for cs in content_scripts:
        for js_file in cs.get("js", []):
            assert (EXT_DIR / js_file).exists(), f"Content script {js_file} does not exist"
        for css_file in cs.get("css", []):
            assert (EXT_DIR / css_file).exists(), f"Content CSS {css_file} does not exist"


def test_icons_exist_and_are_valid_png():
    """Verify all referenced icons exist and have valid PNG dimensions."""
    manifest_file = EXT_DIR / "manifest.json"
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    icons = manifest.get("icons", {})
    assert "16" in icons
    assert "32" in icons
    assert "48" in icons
    assert "128" in icons

    for size_str, rel_path in icons.items():
        expected_size = int(size_str)
        icon_path = EXT_DIR / rel_path
        assert icon_path.exists(), f"Icon file {rel_path} does not exist"

        data = icon_path.read_bytes()
        # Check PNG magic bytes
        assert data.startswith(b"\x89PNG\r\n\x1a\n"), f"{rel_path} lacks valid PNG header"

        # Read IHDR chunk dimensions
        w, h = struct.unpack(">II", data[16:24])
        assert w == expected_size and h == expected_size, (
            f"Icon {rel_path} dimensions ({w}x{h}) do not match expected {expected_size}x{expected_size}"
        )


def test_popup_files_integrity():
    """Verify popup HTML, CSS, and JS exist and contain required SOC selectors."""
    popup_html = EXT_DIR / "src" / "popup" / "popup.html"
    popup_css = EXT_DIR / "src" / "popup" / "popup.css"
    popup_js = EXT_DIR / "src" / "popup" / "popup.js"

    assert popup_html.exists()
    assert popup_css.exists()
    assert popup_js.exists()

    html_content = popup_html.read_text(encoding="utf-8")
    assert "gauge-progress" in html_content
    assert "btn-investigate" in html_content
    assert "btn-rpa-contain" in html_content
    assert "target-domain" in html_content

    js_content = popup_js.read_text(encoding="utf-8")
    assert "GET_ACTIVE_VERDICT" in js_content
    assert "ESCALATE_INVESTIGATION" in js_content
    assert "TRIGGER_UIPATH" in js_content


def test_service_worker_integrity():
    """Verify background service worker exports and event listener handlers."""
    sw_file = EXT_DIR / "src" / "background" / "service-worker.js"
    assert sw_file.exists()

    sw_content = sw_file.read_text(encoding="utf-8")
    assert "chrome.tabs.onUpdated.addListener" in sw_content
    assert "chrome.tabs.onActivated.addListener" in sw_content
    assert "chrome.runtime.onMessage.addListener" in sw_content
    assert "updateTabBadge" in sw_content
    assert "AEGIS_HIGH_RISK_WARNING" in sw_content


def test_api_service_fallback_heuristics():
    """Test offline heuristic fallback algorithm logic."""
    api_file = EXT_DIR / "src" / "services" / "api.js"
    assert api_file.exists()
    api_content = api_file.read_text(encoding="utf-8")
    assert "localHeuristicFallback" in api_content
    assert "http://127.0.0.1:8000" in api_content

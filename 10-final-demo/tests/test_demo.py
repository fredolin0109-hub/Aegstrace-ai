"""
Phase 10 — Final Integration Demo Tests
Validates: demo_runner CLI, URL analysis simulation, RPA integration, report output
"""
import sys
import os
import json
import tempfile
import pytest

# Ensure modules are importable
DEMO_DIR = os.path.join(os.path.dirname(__file__), "..")
RPA_DIR = os.path.join(DEMO_DIR, "..", "08-uipath-rpa")
sys.path.insert(0, DEMO_DIR)
sys.path.insert(0, RPA_DIR)

from demo_runner import (   # noqa: E402
    simulate_url_analysis,
    DEMO_URLS,
    DEMO_BANNER,
)


# ─────────────────────────────────────────────────────────────────────────────
# DEMO_URLS structure tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDemoUrls:
    def test_five_demo_urls_defined(self):
        assert len(DEMO_URLS) == 5

    def test_each_url_has_required_keys(self):
        required = {"url", "expected_label", "scenario"}
        for entry in DEMO_URLS:
            missing = required - entry.keys()
            assert not missing, f"Missing keys {missing} in entry: {entry}"

    def test_expected_labels_valid(self):
        valid_labels = {"PHISHING", "MALWARE", "BENIGN"}
        for entry in DEMO_URLS:
            assert entry["expected_label"] in valid_labels, (
                f"Invalid label '{entry['expected_label']}' for URL: {entry['url']}"
            )

    def test_at_least_one_phishing(self):
        phishing = [u for u in DEMO_URLS if u["expected_label"] == "PHISHING"]
        assert len(phishing) >= 1

    def test_at_least_one_benign(self):
        benign = [u for u in DEMO_URLS if u["expected_label"] == "BENIGN"]
        assert len(benign) >= 1

    def test_banner_is_nonempty(self):
        assert DEMO_BANNER.strip()


# ─────────────────────────────────────────────────────────────────────────────
# simulate_url_analysis tests
# ─────────────────────────────────────────────────────────────────────────────

class TestUrlAnalysis:
    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_returns_dict(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        assert isinstance(result, dict)

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_result_has_required_keys(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        required = {"incident_id", "url", "threat_label", "threat_score", "confidence", "iocs"}
        missing = required - result.keys()
        assert not missing, f"Missing keys {missing} for URL: {url_info['url']}"

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_threat_score_in_range(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        assert 0 <= result["threat_score"] <= 100, (
            f"Score {result['threat_score']} out of range for {url_info['url']}"
        )

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_confidence_in_range(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        assert 0.0 <= result["confidence"] <= 1.0

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_threat_label_valid(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        assert result["threat_label"] in {"PHISHING", "MALWARE", "BENIGN"}

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_iocs_is_list(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=9001)
        assert isinstance(result["iocs"], list)

    @pytest.mark.parametrize("url_info", DEMO_URLS)
    def test_incident_id_matches(self, url_info):
        result = simulate_url_analysis(url_info, incident_id=7777)
        assert result["incident_id"] == 7777

    def test_phishing_url_scores_high(self):
        phishing_url = {
            "url": "http://secure-login-paypal.phish-attack.xyz/verify?token=abc123",
            "expected_label": "PHISHING",
            "scenario": "test",
        }
        result = simulate_url_analysis(phishing_url, incident_id=1)
        assert result["threat_score"] >= 30, (
            f"Expected higher score for phishing URL, got {result['threat_score']}"
        )

    def test_benign_github_scores_low(self):
        benign_url = {
            "url": "https://github.com/fredolin0109-hub/Aegstrace-ai",
            "expected_label": "BENIGN",
            "scenario": "test",
        }
        result = simulate_url_analysis(benign_url, incident_id=1)
        assert result["threat_score"] < 70, (
            f"GitHub URL scored too high: {result['threat_score']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI / integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDemoRunnerCLI:
    def test_demo_runner_file_exists(self):
        assert os.path.isfile(os.path.join(DEMO_DIR, "demo_runner.py"))

    def test_presentation_md_exists(self):
        assert os.path.isfile(os.path.join(DEMO_DIR, "PRESENTATION.md"))

    def test_run_demo_produces_report(self):
        """Run demo_runner --fast and check report JSON is valid."""
        import subprocess
        python = sys.executable
        runner = os.path.join(DEMO_DIR, "demo_runner.py")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [python, runner, "--fast", "--output", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"demo_runner exited with {result.returncode}\nstderr: {result.stderr}"
            )
            with open(tmp_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            assert "summary" in report
            assert report["summary"]["total_urls"] == 5
            assert "url_results" in report
            assert len(report["url_results"]) == 5
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

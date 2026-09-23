"""
Phase 08 — UiPath Risk Alert Workflow & Email Template Tests
Validates: AEGISTRACE_RiskAlert.xaml arguments, template tokens, integration artifacts.
"""
import os
import xml.etree.ElementTree as ET
import pytest

RPA_DIR = os.path.join(os.path.dirname(__file__), "..")
WORKFLOWS_DIR = os.path.join(RPA_DIR, "workflows")
TEMPLATES_DIR = os.path.join(RPA_DIR, "email-templates")
INTEGRATION_DIR = os.path.join(RPA_DIR, "integration")


class TestRiskAlertWorkflowXAML:
    @pytest.fixture(scope="class")
    def xaml_path(self):
        p = os.path.join(WORKFLOWS_DIR, "AEGISTRACE_RiskAlert.xaml")
        assert os.path.exists(p), "AEGISTRACE_RiskAlert.xaml missing"
        return p

    def test_xaml_is_valid_xml(self, xaml_path):
        tree = ET.parse(xaml_path)
        root = tree.getroot()
        assert root is not None

    def test_required_in_arguments_present(self, xaml_path):
        content = open(xaml_path, "r", encoding="utf-8").read()
        required_in_args = [
            "in_IncidentId",
            "in_URL",
            "in_RiskScore",
            "in_RiskLevel",
            "in_Classification",
            "in_Reasons",
            "in_Timestamp",
            "in_RecipientEmail",
        ]
        for arg in required_in_args:
            assert f'Name="{arg}"' in content, f"Argument {arg} missing from AEGISTRACE_RiskAlert.xaml"

    def test_required_out_arguments_present(self, xaml_path):
        content = open(xaml_path, "r", encoding="utf-8").read()
        required_out_args = [
            "out_Status",
            "out_EmailStatus",
            "out_Message",
            "out_ExecutionId",
        ]
        for arg in required_out_args:
            assert f'Name="{arg}"' in content, f"Argument {arg} missing from AEGISTRACE_RiskAlert.xaml"


class TestEmailTemplates:
    def test_templates_exist(self):
        high = os.path.join(TEMPLATES_DIR, "high-risk.html")
        med = os.path.join(TEMPLATES_DIR, "medium-risk.html")
        assert os.path.exists(high), "high-risk.html missing"
        assert os.path.exists(med), "medium-risk.html missing"

    @pytest.mark.parametrize("tmpl_name", ["high-risk.html", "medium-risk.html"])
    def test_template_placeholders(self, tmpl_name):
        path = os.path.join(TEMPLATES_DIR, tmpl_name)
        content = open(path, "r", encoding="utf-8").read()
        required_tokens = [
            "{{incident_id}}",
            "{{url}}",
            "{{risk_score}}",
            "{{classification}}",
            "{{risk_level}}",
            "{{reasons}}",
            "{{timestamp}}",
        ]
        for token in required_tokens:
            assert token in content, f"Placeholder {token} missing in {tmpl_name}"


class TestIntegrationArtifacts:
    def test_api_spec_exists(self):
        spec = os.path.join(INTEGRATION_DIR, "api-spec.md")
        assert os.path.exists(spec)

    def test_payload_examples_exists_and_valid_json(self):
        import json
        payloads = os.path.join(INTEGRATION_DIR, "payload-examples.json")
        assert os.path.exists(payloads)
        with open(payloads, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "high_risk_alert" in data
        assert "medium_risk_alert" in data
        assert "low_risk_alert" in data
        assert "uipath_callback_success" in data

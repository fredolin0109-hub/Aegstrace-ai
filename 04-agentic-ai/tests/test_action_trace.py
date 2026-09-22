import pytest
from datetime import datetime
from action_trace import ActionTrace, ActionTraceItem


def test_action_trace_item_creation():
    item = ActionTraceItem(
        action_type="DETECT",
        tool_name="analyze_url",
        tool_input={"url": "https://example.com"},
        tool_output={"risk_score": 0.10},
        decision_rationale="Evaluated as low risk",
        status="SUCCESS",
    )
    assert item.action_type == "DETECT"
    assert item.tool_name == "analyze_url"
    assert item.status == "SUCCESS"
    assert isinstance(item.timestamp, datetime)
    data = item.to_dict()
    assert data["action_type"] == "DETECT"
    assert "timestamp" in data


def test_action_trace_initial_state():
    trace = ActionTrace(url="https://test.com", url_scan_id=42, depth="deep")
    assert trace.url == "https://test.com"
    assert trace.url_scan_id == 42
    assert trace.depth == "deep"
    assert trace.initial_risk_score == 0.0
    assert trace.final_risk_score == 0.0
    assert trace.decision == "SAFE_PASS"
    assert trace.incident_created is False
    assert len(trace.steps) == 0
    assert len(trace.evidence_collected) == 0


def test_action_trace_record_steps():
    trace = ActionTrace(url="https://test.com")
    step1 = trace.record_step(
        action_type="DETECT",
        tool_name="analyze_url",
        tool_input={"url": "https://test.com"},
        tool_output={"score": 0.05},
        decision_rationale="Baseline check passed",
    )
    assert len(trace.steps) == 1
    assert step1.action_type == "DETECT"

    trace.record_step(
        action_type="INVESTIGATE",
        tool_name="threat_lookup",
        tool_input={"domain": "test.com"},
        tool_output={"category": "SAFE"},
        decision_rationale="Threat lookup clear",
    )
    assert len(trace.steps) == 2
    assert trace.steps[1].tool_name == "threat_lookup"


def test_action_trace_evidence_deduplication():
    trace = ActionTrace(url="https://test.com")
    trace.add_evidence("Evidence alpha")
    trace.add_evidence("Evidence beta")
    trace.add_evidence("Evidence alpha")  # Duplicate
    trace.add_evidence(["Evidence gamma", "Evidence beta"])  # Partial duplicate

    assert len(trace.evidence_collected) == 3
    assert trace.evidence_collected == ["Evidence alpha", "Evidence beta", "Evidence gamma"]


def test_action_trace_state_mutators():
    trace = ActionTrace(url="https://test.com")
    trace.set_initial_risk(0.35, "SUSPICIOUS")
    assert trace.initial_risk_score == 0.35
    assert trace.classification == "SUSPICIOUS"

    trace.set_final_risk(0.85, "HIGH_RISK")
    assert trace.final_risk_score == 0.85
    assert trace.classification == "HIGH_RISK"

    trace.set_decision("TRIGGER_AUTOMATED_RESPONSE", "BLOCK_AND_CONTAIN")
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.recommended_action == "BLOCK_AND_CONTAIN"

    trace.set_incident(101, "INC-20260922-0001")
    assert trace.incident_created is True
    assert trace.incident_id == 101
    assert trace.incident_number == "INC-20260922-0001"

    trace.set_verification({"verified": True, "containment_status": "CONTAINED"})
    assert trace.verification_results["containment_status"] == "CONTAINED"


def test_action_trace_serialization():
    trace = ActionTrace(url="https://test.com")
    trace.set_initial_risk(0.1, "SAFE")
    trace.set_final_risk(0.1, "SAFE")
    trace.record_step("DETECT", "tool1", {}, {}, "rationale")

    d = trace.to_dict()
    assert d["url"] == "https://test.com"
    assert len(d["action_trace"]) == 1
    assert d["action_trace"][0]["action_type"] == "DETECT"

    summary = trace.export_summary()
    assert summary["target"] == "https://test.com"
    assert summary["verdict"] == "SAFE_PASS"
    assert summary["steps_count"] == 1


def test_action_trace_save_to_db_none():
    trace = ActionTrace(url="https://test.com")
    trace.record_step("DETECT", "tool1", {}, {}, "rationale")
    records = trace.save_to_db(None)
    assert records == []

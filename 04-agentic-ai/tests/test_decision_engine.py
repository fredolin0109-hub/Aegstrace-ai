import pytest
from decision_engine import DecisionEngine, DecisionResult


@pytest.fixture
def engine():
    return DecisionEngine()


def test_decision_low_risk(engine):
    res = engine.evaluate(
        risk_score=0.10,
        classification="SAFE",
        evidence=[],
        depth="standard",
    )
    assert res.decision == "SAFE_PASS"
    assert res.recommended_action == "ALLOW"
    assert res.risk_tier == "LOW"
    assert res.should_create_incident is False
    assert res.incident_severity is None
    assert res.should_trigger_uipath is False
    assert res.uipath_action_type is None


def test_decision_medium_risk_standard(engine):
    res = engine.evaluate(
        risk_score=0.45,
        classification="SUSPICIOUS",
        evidence=["Multiple hyphens in domain"],
        depth="standard",
    )
    assert res.decision == "MONITOR"
    assert res.recommended_action == "LOG_AND_WATCH"
    assert res.risk_tier == "MEDIUM"
    assert res.should_create_incident is False
    assert res.should_trigger_uipath is False


def test_decision_medium_risk_deep(engine):
    res = engine.evaluate(
        risk_score=0.45,
        classification="SUSPICIOUS",
        evidence=["Elevated entropy observed"],
        depth="deep",
    )
    assert res.decision == "ESCALATE_INCIDENT"
    assert res.recommended_action == "SOC_REVIEW"
    assert res.risk_tier == "MEDIUM"
    assert res.should_create_incident is True
    assert res.incident_severity == "MEDIUM"
    assert res.should_trigger_uipath is False


def test_decision_high_risk(engine):
    res = engine.evaluate(
        risk_score=0.75,
        classification="HIGH_RISK",
        evidence=["Credential harvesting keywords"],
        depth="standard",
    )
    assert res.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert res.recommended_action == "BLOCK_AND_CONTAIN"
    assert res.risk_tier == "HIGH"
    assert res.should_create_incident is True
    assert res.incident_severity == "HIGH"
    assert res.should_trigger_uipath is True
    assert res.uipath_action_type == "CONTAIN_HOST"


def test_decision_critical_risk(engine):
    res = engine.evaluate(
        risk_score=0.92,
        classification="HIGH_RISK",
        evidence=["Known malicious phishing lure"],
        depth="standard",
    )
    assert res.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert res.recommended_action == "BLOCK_AND_CONTAIN"
    assert res.risk_tier == "CRITICAL"
    assert res.incident_severity == "CRITICAL"
    assert res.should_trigger_uipath is True


def test_decision_known_safe_override(engine):
    res = engine.evaluate(
        risk_score=0.40,
        classification="SUSPICIOUS",
        evidence=[],
        domain_category="SAFE",
    )
    assert res.decision == "SAFE_PASS"
    assert res.recommended_action == "ALLOW"
    assert res.should_create_incident is False


def test_decision_known_malicious_override(engine):
    res = engine.evaluate(
        risk_score=0.25,
        classification="SAFE",
        evidence=[],
        domain_category="MALICIOUS",
    )
    assert res.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert res.should_create_incident is True
    assert res.should_trigger_uipath is True
    assert res.uipath_action_type == "CONTAIN_HOST"


def test_decision_redirect_loop_triggers_automated_response(engine):
    res = engine.evaluate(
        risk_score=0.30,
        classification="SAFE",
        evidence=[],
        has_redirect_loop=True,
    )
    assert res.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert res.should_create_incident is True
    assert res.should_trigger_uipath is True


def test_decision_force_escalate_low_risk(engine):
    res = engine.evaluate(
        risk_score=0.20,
        classification="SAFE",
        force_escalate=True,
    )
    assert res.decision == "ESCALATE_INCIDENT"
    assert res.recommended_action == "SOC_REVIEW"
    assert res.should_create_incident is True
    assert res.incident_severity == "MEDIUM"
    assert res.should_trigger_uipath is False


def test_decision_force_escalate_high_risk(engine):
    res = engine.evaluate(
        risk_score=0.80,
        classification="HIGH_RISK",
        force_escalate=True,
    )
    assert res.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert res.recommended_action == "BLOCK_AND_CONTAIN"
    assert res.should_create_incident is True
    assert res.incident_severity == "HIGH"
    assert res.should_trigger_uipath is True

import pytest
from agent import AegisAgent


@pytest.fixture
def agent():
    return AegisAgent()


def test_agent_benign_url_executes_all_5_phases(agent):
    trace = agent.investigate(
        url="https://www.google.com",
        depth="standard",
    )
    assert trace.url == "https://www.google.com"
    assert trace.classification == "SAFE"
    assert trace.decision == "SAFE_PASS"
    assert trace.recommended_action == "ALLOW"
    assert trace.incident_created is False
    assert trace.final_risk_score < 0.35

    # Verify all 5 phases represented in trace steps
    action_types = [s.action_type for s in trace.steps]
    assert "DETECT" in action_types
    assert "INVESTIGATE" in action_types
    assert "DECIDE" in action_types
    assert "ACT" in action_types
    assert "VERIFY" in action_types

    # Verification state
    assert trace.verification_results is not None
    assert trace.verification_results["verified"] is True


def test_agent_high_risk_triggers_incident_and_uipath(agent):
    trace = agent.investigate(
        url="http://192.168.1.1/paypal-login-security.php",
        depth="deep",
    )
    assert trace.classification == "HIGH_RISK"
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.recommended_action == "BLOCK_AND_CONTAIN"
    assert trace.incident_created is True
    assert trace.incident_id is not None
    assert trace.incident_number.startswith("INC-")
    assert len(trace.evidence_collected) > 0

    # Verify tools invoked
    tools_used = [s.tool_name for s in trace.steps]
    assert "analyze_url" in tools_used
    assert "threat_lookup" in tools_used
    assert "domain_check" in tools_used
    assert "decision_engine" in tools_used
    assert "create_incident" in tools_used
    assert "trigger_uipath" in tools_used
    assert "verify_response" in tools_used

    # Verification validation
    assert trace.verification_results["containment_status"] == "CONTAINED"
    assert trace.verification_results["ticket_created"] is True
    assert trace.verification_results["ticket_id"] is not None
    assert trace.verification_results["verified"] is True


def test_agent_known_malicious_domain(agent):
    trace = agent.investigate("http://paypa1.com/login")
    assert trace.classification == "HIGH_RISK"
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.incident_created is True
    assert any("paypa1.com" in ev for ev in trace.evidence_collected)


def test_agent_redirect_loop_triggers_containment(agent):
    chain = ["http://hop-b.org", "http://hop-c.org", "http://hop-a.org"]
    trace = agent.investigate(
        url="http://hop-a.org",
        redirect_chain=chain,
        depth="deep",
    )
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.incident_created is True
    assert any("redirect cycle/loop" in ev for ev in trace.evidence_collected)


def test_agent_force_escalation(agent):
    trace = agent.investigate(
        url="https://normal-page.org/test",
        force_escalate=True,
    )
    assert trace.incident_created is True
    assert trace.incident_id is not None
    assert trace.incident_number is not None


def test_agent_empty_or_none_url_raises_error(agent):
    with pytest.raises(ValueError):
        agent.investigate("")

    with pytest.raises(ValueError):
        agent.investigate("   ")

    with pytest.raises(ValueError):
        agent.investigate(None)


def test_agent_newly_registered_domain(agent):
    trace = agent.investigate(
        url="http://account-verification-portal.xyz/login",
        domain_age_days=14,
    )
    assert trace.classification == "HIGH_RISK"
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.incident_created is True
    assert any("Newly registered domain" in ev for ev in trace.evidence_collected)


def test_agent_homograph_brand_spoof(agent):
    # 'о' is Cyrillic \u043e visually identical to 'o'
    trace = agent.investigate("http://g\u043e\u043egle-login.security.com/auth")
    assert trace.decision == "TRIGGER_AUTOMATED_RESPONSE"
    assert trace.incident_created is True
    assert any("Homograph" in ev for ev in trace.evidence_collected)

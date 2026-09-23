"""
Phase 08 — UiPath RPA Dispatcher Tests
Tests: simulation mode dispatch, all 6 actions, result schema, error handling
"""
import sys
import os
import pytest

# Ensure dispatcher module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dispatcher import UiPathDispatcher, SUPPORTED_ACTIONS  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sim_dispatcher():
    """UiPathDispatcher running in simulation (offline) mode."""
    return UiPathDispatcher(simulation_mode=True)


# ---------------------------------------------------------------------------
# Structural / schema tests
# ---------------------------------------------------------------------------

class TestSupportedActions:
    def test_actions_defined(self):
        assert len(SUPPORTED_ACTIONS) >= 6

    def test_expected_action_names(self):
        expected = {
            "CONTAIN_HOST",
            "BLOCK_DOMAIN",
            "CREATE_TICKET",
            "NOTIFY_SOC",
            "ISOLATE_USER",
            "GENERATE_REPORT",
            "RISK_ALERT",
        }
        assert expected.issubset(set(SUPPORTED_ACTIONS.keys()))

    def test_each_action_has_description(self):
        for action, config in SUPPORTED_ACTIONS.items():
            assert "description" in config, f"'{action}' missing 'description'"
            assert config["description"], f"'{action}' has empty description"

    def test_each_action_has_sample_result(self):
        for action, config in SUPPORTED_ACTIONS.items():
            assert callable(config.get("sample_result")), (
                f"'{action}' missing callable 'sample_result'"
            )


# ---------------------------------------------------------------------------
# Simulation dispatch tests
# ---------------------------------------------------------------------------

class TestSimulationDispatch:
    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_dispatch_returns_dict(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=1001,
            action_type=action,
            parameters={"test": True},
        )
        assert isinstance(result, dict), f"Expected dict for action '{action}'"

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_result_has_required_keys(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=1001,
            action_type=action,
            parameters={"test": True},
        )
        required_keys = {"execution_id", "status", "action_type", "incident_id", "result_payload"}
        missing = required_keys - result.keys()
        assert not missing, f"Missing keys {missing} for action '{action}'"

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_result_action_type_matches_input(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=2001,
            action_type=action,
            parameters={},
        )
        assert result["action_type"] == action

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_result_incident_id_matches(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=3001,
            action_type=action,
            parameters={},
        )
        assert result["incident_id"] == 3001

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_execution_id_nonempty(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=4001,
            action_type=action,
            parameters={},
        )
        assert result["execution_id"], f"execution_id should be non-empty for '{action}'"

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_status_is_success_in_simulation(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=5001,
            action_type=action,
            parameters={},
        )
        assert result["status"] == "SUCCESS"

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_is_simulation_flag_true(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=6001,
            action_type=action,
            parameters={},
        )
        assert result.get("is_simulation") is True

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_result_payload_is_dict(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=7001,
            action_type=action,
            parameters={},
        )
        assert isinstance(result["result_payload"], dict), (
            f"result_payload should be dict for '{action}'"
        )

    @pytest.mark.parametrize("action", SUPPORTED_ACTIONS)
    def test_result_payload_has_status(self, sim_dispatcher, action):
        result = sim_dispatcher.dispatch(
            incident_id=8001,
            action_type=action,
            parameters={},
        )
        payload = result["result_payload"]
        assert "status" in payload, (
            f"result_payload missing 'status' for action '{action}'"
        )


# ---------------------------------------------------------------------------
# Error / edge-case tests
# ---------------------------------------------------------------------------

class TestDispatcherEdgeCases:
    def test_invalid_action_raises_value_error(self, sim_dispatcher):
        with pytest.raises(ValueError, match="Unsupported UiPath action"):
            sim_dispatcher.dispatch(
                incident_id=9999,
                action_type="invalid_action_xyz",
                parameters={},
            )

    def test_case_insensitive_action(self, sim_dispatcher):
        """dispatch() normalises action names to uppercase."""
        result = sim_dispatcher.dispatch(
            incident_id=1,
            action_type="contain_host",  # lowercase input
            parameters={},
        )
        assert result["action_type"] == "CONTAIN_HOST"

    def test_simulation_mode_flag_set(self):
        d = UiPathDispatcher(simulation_mode=True)
        assert d.simulation_mode is True

    def test_instantiation_without_args(self):
        # Should not raise even with missing env vars (defaults to simulation)
        d = UiPathDispatcher()
        assert d is not None

    def test_execution_id_prefix(self, sim_dispatcher):
        result = sim_dispatcher.dispatch(
            incident_id=1,
            action_type="BLOCK_DOMAIN",
            parameters={},
        )
        assert result["execution_id"].startswith("UIPATH-")

    def test_no_error_message_in_simulation(self, sim_dispatcher):
        result = sim_dispatcher.dispatch(
            incident_id=1,
            action_type="NOTIFY_SOC",
            parameters={},
        )
        assert result.get("error_message") is None

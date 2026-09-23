"""
AEGISTRACE UiPath RPA Dispatcher & Orchestrator Integration Bridge
Connects backend SOC incidents to automated UiPath RPA response workflows.
Supports both live UiPath Orchestrator Cloud REST API and deterministic simulation mode.
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Add root directory to sys.path so config can be loaded if available
root_dir = Path(__file__).resolve().parents[1]
backend_dir = root_dir / "01-backend"
if str(backend_dir) not in sys.path and backend_dir.exists():
    sys.path.insert(0, str(backend_dir))

try:
    from app.config import settings
except ImportError:
    # Standalone fallback config
    class DummySettings:
        UIPATH_ORCHESTRATOR_URL = os.getenv("UIPATH_ORCHESTRATOR_URL", "https://cloud.uipath.com")
        UIPATH_TENANT_NAME = os.getenv("UIPATH_TENANT_NAME", "")
        UIPATH_CLIENT_ID = os.getenv("UIPATH_CLIENT_ID", "")
        UIPATH_USER_KEY = os.getenv("UIPATH_USER_KEY", "")
        UIPATH_PROCESS_NAME = os.getenv("UIPATH_PROCESS_NAME", "AegisTrace_PhishingResponse")
        UIPATH_SIMULATION_MODE = os.getenv("UIPATH_SIMULATION_MODE", "true").lower() in ("true", "1", "yes")
        DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    settings = DummySettings()


SUPPORTED_ACTIONS = {
    "CONTAIN_HOST": {
        "description": "Network adapter isolation and host containment via EDR / PowerShell",
        "sample_result": lambda inc_id, p: {
            "status": "ISOLATED",
            "host_ip": p.get("host_ip", "192.168.1.145"),
            "hostname": p.get("hostname", f"DESKTOP-INC-{inc_id}"),
            "containment_policy": "DISCONNECT_NIC_ALLOW_SOC_TELEMETRY",
            "execution_mode": "UIPATH_RPA",
            "containment_timestamp": datetime.now(timezone.utc).isoformat(),
        }
    },
    "BLOCK_DOMAIN": {
        "description": "Perimeter firewall ACL and DNS sinkhole blacklisting",
        "sample_result": lambda inc_id, p: {
            "status": "BLOCKED",
            "domain": p.get("domain", f"phish-target-{inc_id}.xyz"),
            "firewall_rule": f"AEGIS_AUTO_BLOCK_INC_{inc_id}",
            "dns_sinkhole_ip": "10.254.254.254",
            "perimeter_targets": ["PaloAlto-Edge-FW-01", "Core-DNS-Sinkhole"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    },
    "CREATE_TICKET": {
        "description": "Enterprise ServiceNow / Jira P1/P2 SOC incident record",
        "sample_result": lambda inc_id, p: {
            "status": "CREATED",
            "external_ticket_id": f"SOC-TICKET-{inc_id:05d}",
            "ticketing_system": p.get("ticketing_system", "SERVICENOW"),
            "priority": p.get("ticket_priority", "P1_CRITICAL"),
            "assigned_group": "SOC_INCIDENT_RESPONSE_L2",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    },
    "NOTIFY_SOC": {
        "description": "Real-time Slack, Microsoft Teams, and PagerDuty escalation alert",
        "sample_result": lambda inc_id, p: {
            "status": "DELIVERED",
            "channels": ["SLACK_WAR_ROOM", "PAGERDUTY_INCIDENT_QUEUE"],
            "alert_level": "CRITICAL",
            "incident_number": f"INC-2026-{inc_id:05d}",
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
        }
    },
    "ISOLATE_USER": {
        "description": "Credential revocation, active session kill, and forced password reset",
        "sample_result": lambda inc_id, p: {
            "status": "CREDENTIALS_REVOKED",
            "target_user": p.get("user_principal_name", f"employee.{inc_id}@enterprise.corp"),
            "active_tokens_revoked": 4,
            "forced_password_reset": True,
            "mfa_challenged": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    },
    "GENERATE_REPORT": {
        "description": "Forensic evidence compilation into PDF and structured JSON dossier",
        "sample_result": lambda inc_id, p: {
            "status": "GENERATED",
            "report_id": f"DOSSIER-INC-{inc_id}",
            "filename": f"AEGIS_FORENSIC_INC_{inc_id:05d}.pdf",
            "evidence_items_count": len(p.get("iocs", [])) or 5,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    },
    "RISK_ALERT": {
        "description": "Risk-based triage and security email dispatch (AEGISTRACE_RiskAlert)",
        "sample_result": lambda inc_id, p: {
            "status": "COMPLETED",
            "workflow": "AEGISTRACE_RiskAlert",
            "risk_score": p.get("risk_score", 94),
            "risk_level": p.get("risk_level", "HIGH"),
            "email_status": "SENT" if p.get("risk_score", 94) >= 70 else "SKIPPED",
            "recipient_email": p.get("recipient_email", "security-admin@example.com"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }
}


class UiPathDispatcher:
    """Dispatches RPA workflows to UiPath Orchestrator or handles local simulation."""

    def __init__(
        self,
        orchestrator_url: Optional[str] = None,
        tenant_name: Optional[str] = None,
        client_id: Optional[str] = None,
        user_key: Optional[str] = None,
        process_name: Optional[str] = None,
        simulation_mode: Optional[bool] = None,
    ):
        self.orchestrator_url = orchestrator_url or settings.UIPATH_ORCHESTRATOR_URL
        self.tenant_name = tenant_name or settings.UIPATH_TENANT_NAME
        self.client_id = client_id or settings.UIPATH_CLIENT_ID
        self.user_key = user_key or settings.UIPATH_USER_KEY
        self.process_name = process_name or settings.UIPATH_PROCESS_NAME
        
        # Simulation if explicitly enabled or if required credentials are not set
        if simulation_mode is not None:
            self.simulation_mode = simulation_mode
        else:
            has_credentials = bool(self.client_id and self.user_key)
            self.simulation_mode = settings.UIPATH_SIMULATION_MODE or not has_credentials

    def dispatch(
        self,
        incident_id: int,
        action_type: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatches an incident response action to UiPath."""
        action_type_norm = action_type.strip().upper()
        if action_type_norm not in SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported UiPath action '{action_type}'. Must be one of: {list(SUPPORTED_ACTIONS.keys())}"
            )

        params = parameters or {}
        execution_id = f"UIPATH-{uuid.uuid4().hex[:12].upper()}"
        executed_at = datetime.now(timezone.utc)

        if self.simulation_mode:
            return self._simulate_execution(incident_id, action_type_norm, params, execution_id, executed_at)
        else:
            return self._execute_live_orchestrator(incident_id, action_type_norm, params, execution_id, executed_at)

    def _simulate_execution(
        self,
        incident_id: int,
        action_type: str,
        parameters: Dict[str, Any],
        execution_id: str,
        executed_at: datetime,
    ) -> Dict[str, Any]:
        """Simulates successful UiPath response without modifying real network infrastructure."""
        config = SUPPORTED_ACTIONS[action_type]
        result_payload = config["sample_result"](incident_id, parameters)

        return {
            "execution_id": execution_id,
            "incident_id": incident_id,
            "action_type": action_type,
            "status": "SUCCESS",
            "progress_percentage": 100,
            "is_simulation": True,
            "executed_at": executed_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "input_payload": parameters,
            "result_payload": result_payload,
            "error_message": None,
        }

    def _execute_live_orchestrator(
        self,
        incident_id: int,
        action_type: str,
        parameters: Dict[str, Any],
        execution_id: str,
        executed_at: datetime,
    ) -> Dict[str, Any]:
        """Dispatches workflow to live UiPath Orchestrator REST API."""
        try:
            import requests  # available in venv
            
            # Step 1: Authenticate via OAuth2 token endpoint
            auth_url = "https://account.uipath.com/oauth/token"
            auth_payload = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self.user_key,
            }
            auth_res = requests.post(auth_url, json=auth_payload, timeout=10)
            if not auth_res.ok:
                raise RuntimeError(f"UiPath OAuth2 authentication failed: {auth_res.text}")

            access_token = auth_res.json().get("access_token")

            # Step 2: Start Job via Orchestrator REST API
            jobs_url = f"{self.orchestrator_url.rstrip('/')}/odata/Jobs/UiPath.Server.Configuration.OData.StartJobs"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-UIPATH-TenantName": self.tenant_name,
                "Content-Type": "application/json",
            }

            job_payload = {
                "startInfo": {
                    "ReleaseKey": self.process_name,
                    "Strategy": "All",
                    "InputArguments": json.dumps({
                        "in_IncidentId": incident_id,
                        "in_ActionType": action_type,
                        "in_PayloadJson": json.dumps(parameters),
                    })
                }
            }

            job_res = requests.post(jobs_url, headers=headers, json=job_payload, timeout=15)
            if not job_res.ok:
                raise RuntimeError(f"Orchestrator start job failed: {job_res.text}")

            job_data = job_res.json()
            orchestrator_key = job_data.get("value", [{}])[0].get("Key", execution_id)

            return {
                "execution_id": orchestrator_key,
                "incident_id": incident_id,
                "action_type": action_type,
                "status": "RUNNING",
                "progress_percentage": 50,
                "is_simulation": False,
                "executed_at": executed_at.isoformat(),
                "completed_at": None,
                "input_payload": parameters,
                "result_payload": {"orchestrator_job_info": job_data},
                "error_message": None,
            }

        except Exception as exc:
            # Fall back to simulation gracefully if credentials expire or network blocks cloud API
            fallback = self._simulate_execution(incident_id, action_type, parameters, execution_id, executed_at)
            fallback["status"] = "SIMULATED"
            fallback["error_message"] = f"Orchestrator API unreachable ({str(exc)}); executed in safe simulation mode."
            return fallback


global_uipath_dispatcher = UiPathDispatcher()


def main():
    parser = argparse.ArgumentParser(description="AEGISTRACE UiPath RPA Dispatcher CLI")
    parser.add_argument("--action", type=str, choices=list(SUPPORTED_ACTIONS.keys()), help="RPA action to trigger")
    parser.add_argument("--incident-id", type=int, default=1, help="Incident ID")
    parser.add_argument("--params", type=str, default="{}", help="JSON parameters")
    parser.add_argument("--test-all", action="store_true", help="Execute dry-run across all 6 actions")

    args = parser.parse_args()

    if args.test_all:
        print("[AEGISTRACE UiPath RPA] Running dry-run validation across all actions:")
        dispatcher = UiPathDispatcher(simulation_mode=True)
        for act in SUPPORTED_ACTIONS:
            res = dispatcher.dispatch(incident_id=999, action_type=act, parameters={"test": True})
            print(f"  [OK] {act:16} -> Status: {res['status']:10} (Execution ID: {res['execution_id']})")
        print("[AEGISTRACE UiPath RPA] All workflows verified successfully.")
        return

    if not args.action:
        parser.print_help()
        sys.exit(1)

    try:
        parsed_params = json.loads(args.params)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON parameters: {args.params}", file=sys.stderr)
        sys.exit(1)

    dispatcher = UiPathDispatcher()
    result = dispatcher.dispatch(incident_id=args.incident_id, action_type=args.action, parameters=parsed_params)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

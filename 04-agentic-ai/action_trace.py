import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

# Ensure repo root and submodules are in sys.path
_curr = Path(__file__).resolve()
while _curr.parent != _curr:
    if (_curr / "01-backend").exists() and (_curr / "02-dsa-engine").exists():
        for sub in ["01-backend", "02-dsa-engine", "03-aiml-engine", "03-aiml-engine/src", "04-agentic-ai"]:
            sp = _curr / sub
            if sp.exists() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        break
    _curr = _curr.parent


@dataclass
class ActionTraceItem:
    """Represents an individual step or tool invocation executed by the Agent."""
    action_type: str  # DETECT, INVESTIGATE, DECIDE, ACT, VERIFY
    tool_name: str
    tool_input: Dict[str, Any] = field(default_factory=dict)
    tool_output: Dict[str, Any] = field(default_factory=dict)
    decision_rationale: str = ""
    status: str = "SUCCESS"  # SUCCESS, FAILED, RUNNING
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output,
            "decision_rationale": self.decision_rationale,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
        }


class ActionTrace:
    """
    Auditable action trace tracker storing initial risk, investigation steps,
    evidence collected, decisions, actions requested, and verification results.
    """

    def __init__(
        self,
        url: str,
        url_scan_id: Optional[int] = None,
        depth: str = "standard",
    ):
        self.url: str = url
        self.url_scan_id: Optional[int] = url_scan_id
        self.depth: str = depth

        # Risk state
        self.initial_risk_score: float = 0.0
        self.final_risk_score: float = 0.0
        self.classification: str = "SAFE"

        # Decision state
        self.decision: str = "SAFE_PASS"
        self.recommended_action: str = "ALLOW"

        # Incident escalation state
        self.incident_created: bool = False
        self.incident_id: Optional[int] = None
        self.incident_number: Optional[str] = None

        # Trace logs
        self.steps: List[ActionTraceItem] = []
        self.evidence_collected: List[str] = []
        self._evidence_set: set = set()

        # Verification state
        self.verification_results: Optional[Dict[str, Any]] = None

    def record_step(
        self,
        action_type: str,
        tool_name: str,
        tool_input: Dict[str, Any],
        tool_output: Dict[str, Any],
        decision_rationale: str,
        status: str = "SUCCESS",
    ) -> ActionTraceItem:
        """Appends a new auditable action step to the trace."""
        item = ActionTraceItem(
            action_type=action_type,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
            decision_rationale=decision_rationale,
            status=status,
            timestamp=datetime.now(timezone.utc),
        )
        self.steps.append(item)
        return item

    def add_evidence(self, evidence: str | List[str]) -> None:
        """Adds unique evidence items preserving discovery order."""
        if isinstance(evidence, str):
            evidence_list = [evidence]
        else:
            evidence_list = evidence

        for item in evidence_list:
            cleaned = item.strip()
            if cleaned and cleaned not in self._evidence_set:
                self._evidence_set.add(cleaned)
                self.evidence_collected.append(cleaned)

    def set_initial_risk(self, risk_score: float, classification: str) -> None:
        """Sets baseline detection risk score and classification."""
        self.initial_risk_score = round(max(0.0, min(1.0, risk_score)), 2)
        self.classification = classification

    def set_final_risk(self, risk_score: float, classification: str) -> None:
        """Updates final risk score after multi-tool investigation."""
        self.final_risk_score = round(max(0.0, min(1.0, risk_score)), 2)
        self.classification = classification

    def set_decision(self, decision: str, recommended_action: str) -> None:
        """Records final autonomous decision outcome."""
        self.decision = decision
        self.recommended_action = recommended_action

    def set_incident(self, incident_id: int, incident_number: str) -> None:
        """Attaches escalated SOC incident reference."""
        self.incident_created = True
        self.incident_id = incident_id
        self.incident_number = incident_number

    def set_verification(self, verification_data: Dict[str, Any]) -> None:
        """Records post-action containment and response verification."""
        self.verification_results = verification_data

    def to_dict(self) -> Dict[str, Any]:
        """Serializes full action trace to dictionary."""
        return {
            "url": self.url,
            "url_scan_id": self.url_scan_id,
            "depth": self.depth,
            "initial_risk_score": self.initial_risk_score,
            "final_risk_score": self.final_risk_score,
            "classification": self.classification,
            "decision": self.decision,
            "recommended_action": self.recommended_action,
            "incident_created": self.incident_created,
            "incident_id": self.incident_id,
            "incident_number": self.incident_number,
            "evidence_collected": list(self.evidence_collected),
            "verification_results": self.verification_results,
            "action_trace": [step.to_dict() for step in self.steps],
        }

    def export_summary(self) -> Dict[str, Any]:
        """Produces a high-level executive summary of the investigation."""
        return {
            "target": self.url,
            "verdict": self.decision,
            "initial_risk": self.initial_risk_score,
            "final_risk": self.final_risk_score,
            "evidence_count": len(self.evidence_collected),
            "steps_count": len(self.steps),
            "incident_created": self.incident_created,
            "incident_number": self.incident_number,
            "contained": (
                self.verification_results.get("containment_status") == "CONTAINED"
                if self.verification_results
                else False
            ),
        }

    def save_to_db(
        self,
        db: Any,
        scan_id: Optional[int] = None,
        incident_id: Optional[int] = None,
    ) -> List[Any]:
        """
        Persists each trace step as an AgentAction entity into the database.
        Fails safely if database is unavailable or models cannot be imported.
        """
        if db is None:
            return []

        effective_scan_id = scan_id or self.url_scan_id
        effective_incident_id = incident_id or self.incident_id

        try:
            from app.models.agent_action import AgentAction
        except ImportError:
            return []

        created_records = []
        try:
            for step in self.steps:
                action_record = AgentAction(
                    url_scan_id=effective_scan_id,
                    incident_id=effective_incident_id,
                    action_type=step.action_type,
                    tool_name=step.tool_name,
                    tool_input_json=step.tool_input,
                    tool_output_json=step.tool_output,
                    decision_rationale=step.decision_rationale,
                    status=step.status,
                    created_at=step.timestamp,
                )
                db.add(action_record)
                created_records.append(action_record)

            db.commit()
            return created_records
        except Exception as exc:
            db.rollback()
            return []

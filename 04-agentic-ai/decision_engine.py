import math
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


@dataclass
class DecisionResult:
    """Represents the deterministic outcome of the Agentic Decision Engine."""
    decision: str  # SAFE_PASS, MONITOR, ESCALATE_INCIDENT, TRIGGER_AUTOMATED_RESPONSE
    recommended_action: str  # ALLOW, LOG_AND_WATCH, SOC_REVIEW, BLOCK_AND_CONTAIN
    risk_tier: str  # LOW, MEDIUM, HIGH, CRITICAL
    should_create_incident: bool
    incident_severity: Optional[str]  # LOW, MEDIUM, HIGH, CRITICAL or None
    should_trigger_uipath: bool
    uipath_action_type: Optional[str]  # CONTAIN_HOST, BLOCK_DOMAIN, CREATE_TICKET, NOTIFY_SOC or None
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DecisionEngine:
    """
    Deterministic and evidence-grounded decision matrix for cybersecurity investigation.
    Maps evidence, risk scores, and tactical depth to precise operational actions:
    - LOW RISK -> Safe pass, allow traffic
    - MEDIUM RISK -> Monitor or SOC incident review based on investigation depth
    - HIGH RISK -> Immediate automated response, incident generation, and UiPath RPA containment
    """

    def __init__(
        self,
        high_risk_threshold: float = 0.70,
        medium_risk_threshold: float = 0.35,
        critical_threshold: float = 0.85,
    ):
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold
        self.critical_threshold = critical_threshold

    def evaluate(
        self,
        risk_score: float,
        classification: str,
        evidence: Optional[List[str]] = None,
        depth: str = "standard",
        force_escalate: bool = False,
        domain_category: Optional[str] = None,
        has_redirect_loop: bool = False,
        is_known_threat: bool = False,
    ) -> DecisionResult:
        """
        Executes deterministic evaluation across policy matrix.
        Returns a structured DecisionResult.
        """
        evidence_list = evidence or []

        if risk_score is None or (isinstance(risk_score, float) and math.isnan(risk_score)):
            clamped_score = 1.0
        else:
            try:
                clamped_score = round(max(0.0, min(1.0, float(risk_score))), 2)
            except (TypeError, ValueError):
                clamped_score = 1.0

        # 1. Override for verified enterprise allowlisted/legitimate domains
        if domain_category == "SAFE" and not force_escalate:
            return DecisionResult(
                decision="SAFE_PASS",
                recommended_action="ALLOW",
                risk_tier="LOW",
                should_create_incident=False,
                incident_severity=None,
                should_trigger_uipath=False,
                uipath_action_type=None,
                rationale="Verified legitimate domain matching allowlist database with no elevated risk indicators.",
            )

        # 2. Administrative Force Escalation
        if force_escalate:
            is_high = clamped_score >= self.high_risk_threshold or domain_category == "MALICIOUS"
            severity = (
                "CRITICAL" if clamped_score >= self.critical_threshold
                else ("HIGH" if clamped_score >= 0.65 else "MEDIUM")
            )
            decision = "TRIGGER_AUTOMATED_RESPONSE" if is_high else "ESCALATE_INCIDENT"
            action = "BLOCK_AND_CONTAIN" if is_high else "SOC_REVIEW"

            return DecisionResult(
                decision=decision,
                recommended_action=action,
                risk_tier="CRITICAL" if clamped_score >= self.critical_threshold else ("HIGH" if is_high else "MEDIUM"),
                should_create_incident=True,
                incident_severity=severity,
                should_trigger_uipath=is_high,
                uipath_action_type="CONTAIN_HOST" if is_high else None,
                rationale=f"Administrative force escalation engaged. Evaluated risk score: {clamped_score:.2f} ({severity}).",
            )

        # 3. High Risk Tier (Score >= 0.70 OR Known Malicious OR Evasive Redirect Loop)
        if (
            clamped_score >= self.high_risk_threshold
            or domain_category == "MALICIOUS"
            or has_redirect_loop
            or is_known_threat
        ):
            severity = "CRITICAL" if clamped_score >= self.critical_threshold else "HIGH"
            rationale_reasons = []
            if clamped_score >= self.high_risk_threshold:
                rationale_reasons.append(f"risk score {clamped_score:.2f} meets critical threat threshold")
            if domain_category == "MALICIOUS" or is_known_threat:
                rationale_reasons.append("domain identified in threat intelligence database")
            if has_redirect_loop:
                rationale_reasons.append("evasive redirect cycle detected")

            reasons_str = "; ".join(rationale_reasons) if rationale_reasons else f"risk score {clamped_score:.2f}"

            return DecisionResult(
                decision="TRIGGER_AUTOMATED_RESPONSE",
                recommended_action="BLOCK_AND_CONTAIN",
                risk_tier="CRITICAL" if severity == "CRITICAL" else "HIGH",
                should_create_incident=True,
                incident_severity=severity,
                should_trigger_uipath=True,
                uipath_action_type="CONTAIN_HOST",
                rationale=f"Autonomous containment triggered: {reasons_str}. Dispatched incident & UiPath host isolation.",
            )

        # 4. Medium Risk Tier (0.35 <= Score < 0.70)
        if clamped_score >= self.medium_risk_threshold:
            # Under deep investigation or elevated medium (>=0.60), escalate for SOC analyst review
            if depth == "deep" or clamped_score >= 0.60:
                severity = "HIGH" if clamped_score >= 0.65 else "MEDIUM"
                return DecisionResult(
                    decision="ESCALATE_INCIDENT",
                    recommended_action="SOC_REVIEW",
                    risk_tier="MEDIUM",
                    should_create_incident=True,
                    incident_severity=severity,
                    should_trigger_uipath=False,
                    uipath_action_type=None,
                    rationale=f"Elevated risk score {clamped_score:.2f} under {depth} investigation. Escalated to SOC queue.",
                )
            else:
                return DecisionResult(
                    decision="MONITOR",
                    recommended_action="LOG_AND_WATCH",
                    risk_tier="MEDIUM",
                    should_create_incident=False,
                    incident_severity=None,
                    should_trigger_uipath=False,
                    uipath_action_type=None,
                    rationale=f"Moderate risk score {clamped_score:.2f} recorded under standard depth. Traffic logged to telemetry.",
                )

        # 5. Low Risk Tier (Score < 0.35)
        return DecisionResult(
            decision="SAFE_PASS",
            recommended_action="ALLOW",
            risk_tier="LOW",
            should_create_incident=False,
            incident_severity=None,
            should_trigger_uipath=False,
            uipath_action_type=None,
            rationale=f"Risk score {clamped_score:.2f} within benign operating bounds. No malicious signatures detected.",
        )

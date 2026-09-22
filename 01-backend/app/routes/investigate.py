from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.url_scan import URLScan
from app.models.agent_action import AgentAction
from app.models.incident import Incident
from app.schemas.agent import InvestigateRequest, InvestigateResponse, AgentActionTraceItem
from app.schemas.incident import IncidentCreate
from app.services.scan_service import perform_scan
from app.services.incident_service import create_incident

router = APIRouter(prefix="/investigate", tags=["Investigation"])


@router.post("", response_model=InvestigateResponse, summary="Autonomous agentic investigation of suspicious URLs")
def investigate_url(
    payload: InvestigateRequest,
    db: Session = Depends(get_db)
):
    """
    Executes a multi-step investigation pipeline for suspicious or high-risk URLs,
    records immutable action traces, and escalates to an incident if necessary.
    """
    # 1. Retrieve or perform baseline scan
    scan = None
    if payload.url_scan_id:
        scan = db.query(URLScan).filter(URLScan.id == payload.url_scan_id).first()

    if not scan:
        scan = perform_scan(db=db, raw_url=payload.url)

    action_trace = []
    evidence_collected = []

    # Step 1: Baseline Detection
    detect_action = AgentAction(
        url_scan_id=scan.id,
        action_type="DETECT",
        tool_name="threat_signature_analyzer",
        tool_input_json={"url": scan.url, "domain": scan.domain},
        tool_output_json={"risk_score": scan.risk_score, "classification": scan.classification},
        decision_rationale=f"Baseline risk score evaluated at {scan.risk_score:.2f} ({scan.classification}).",
        status="SUCCESS",
    )
    db.add(detect_action)
    action_trace.append(AgentActionTraceItem(
        action_type="DETECT",
        tool_name="threat_signature_analyzer",
        tool_input={"url": scan.url},
        tool_output={"risk_score": scan.risk_score, "classification": scan.classification},
        decision_rationale=f"Baseline detection calculated risk score {scan.risk_score:.2f}.",
        status="SUCCESS",
    ))

    # Step 2: In-Depth Investigation
    investigate_action = AgentAction(
        url_scan_id=scan.id,
        action_type="INVESTIGATE",
        tool_name="domain_reputation_inspector",
        tool_input_json={"domain": scan.domain, "depth": payload.depth},
        tool_output_json={
            "subdomain_count": scan.features_json.get("subdomain_count", 0),
            "is_ip_address": scan.features_json.get("is_ip_address", False),
            "suspicious_keywords": scan.features_json.get("detected_keywords", []),
        },
        decision_rationale="Evaluated domain registration patterns, DNS depth, and obfuscation signatures.",
        status="SUCCESS",
    )
    db.add(investigate_action)

    if scan.features_json.get("is_ip_address"):
        evidence_collected.append("Direct IP address routing bypasses standard domain name validation.")
    if scan.features_json.get("detected_keywords"):
        kws = ", ".join(scan.features_json.get("detected_keywords", []))
        evidence_collected.append(f"High-risk phishing keywords detected: {kws}.")
    if scan.features_json.get("is_suspicious_tld"):
        evidence_collected.append(f"High-abuse top-level domain detected: .{scan.features_json.get('tld')}.")
    if scan.features_json.get("dsa_reputation") == "MALICIOUS":
        evidence_collected.append(f"DSA HashMap identified domain as known malicious ({scan.features_json.get('threat_type', 'THREAT')}).")
    if scan.features_json.get("trie_matched_patterns"):
        pats = ", ".join(scan.features_json.get("trie_matched_patterns"))
        evidence_collected.append(f"DSA Trie detected critical phishing patterns: {pats}.")
    if scan.features_json.get("graph_summary", {}).get("has_redirect_loop"):
        evidence_collected.append("DSA ThreatGraph detected evasive redirect cycle/loop.")

    action_trace.append(AgentActionTraceItem(
        action_type="INVESTIGATE",
        tool_name="domain_reputation_inspector",
        tool_input={"domain": scan.domain},
        tool_output={"evidence": evidence_collected},
        decision_rationale="Investigated domain heuristics, URI parameters, and brand impersonation risks.",
        status="SUCCESS",
    ))

    # Step 3: Autonomous Decision & Escalation
    should_escalate = scan.risk_score >= 0.70 or payload.force_escalate or (scan.risk_score >= 0.40 and payload.depth == "deep")

    if should_escalate:
        decision = "TRIGGER_AUTOMATED_RESPONSE" if scan.risk_score >= 0.70 else "ESCALATE_INCIDENT"
        recommended_action = "BLOCK_AND_CONTAIN" if scan.risk_score >= 0.70 else "SOC_REVIEW"

        # Create incident
        severity = "CRITICAL" if scan.risk_score >= 0.85 else ("HIGH" if scan.risk_score >= 0.65 else "MEDIUM")
        incident_obj = create_incident(
            db=db,
            incident_data=IncidentCreate(
                url=scan.url,
                title=f"Phishing Threat Detected: {scan.domain}",
                description=f"Automated investigation escalated URL {scan.url} with risk score {scan.risk_score}. Evidence: " + "; ".join(evidence_collected or ["Suspicious activity observed"]),
                severity=severity,
                url_scan_id=scan.id,
            ),
            actor="AGENT"
        )
        incident_created = True
        incident_id = incident_obj.id
        incident_number = incident_obj.incident_number
    else:
        decision = "SAFE_PASS" if scan.risk_score < 0.35 else "MONITOR"
        recommended_action = "ALLOW" if scan.risk_score < 0.35 else "LOG_AND_WATCH"
        incident_created = False
        incident_id = None
        incident_number = None

    decide_action = AgentAction(
        url_scan_id=scan.id,
        incident_id=incident_id,
        action_type="DECIDE",
        tool_name="decision_matrix_engine",
        tool_input_json={"risk_score": scan.risk_score, "escalate": should_escalate},
        tool_output_json={"decision": decision, "incident_number": incident_number},
        decision_rationale=f"Decision rendered: {decision}. Incident created: {incident_created}.",
        status="SUCCESS",
    )
    db.add(decide_action)
    db.commit()

    action_trace.append(AgentActionTraceItem(
        action_type="DECIDE",
        tool_name="decision_matrix_engine",
        tool_input={"risk_score": scan.risk_score},
        tool_output={"decision": decision, "incident_id": incident_id},
        decision_rationale=f"Concluded investigation with outcome '{decision}'.",
        status="SUCCESS",
    ))

    return InvestigateResponse(
        url=scan.url,
        url_scan_id=scan.id,
        initial_risk_score=scan.risk_score,
        final_risk_score=scan.risk_score,
        classification=scan.classification,
        decision=decision,
        incident_created=incident_created,
        incident_id=incident_id,
        incident_number=incident_number,
        evidence_collected=evidence_collected,
        action_trace=action_trace,
        recommended_action=recommended_action,
    )

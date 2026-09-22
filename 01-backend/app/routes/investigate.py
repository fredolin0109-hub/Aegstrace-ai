import sys
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

# Ensure 04-agentic-ai is in sys.path
root_dir = Path(__file__).resolve().parents[3]
agent_dir = root_dir / "04-agentic-ai"
if str(agent_dir) not in sys.path and agent_dir.exists():
    sys.path.insert(0, str(agent_dir))

from agent import AegisAgent
from app.database import get_db
from app.schemas.agent import InvestigateRequest, InvestigateResponse, AgentActionTraceItem

router = APIRouter(prefix="/investigate", tags=["Investigation"])


@router.post("", response_model=InvestigateResponse, summary="Autonomous agentic investigation of suspicious URLs")
def investigate_url(
    payload: InvestigateRequest,
    db: Session = Depends(get_db)
):
    """
    Executes a multi-step autonomous investigation pipeline for suspicious or high-risk URLs,
    records immutable action traces across the 5-phase lifecycle (DETECT, INVESTIGATE, DECIDE, ACT, VERIFY),
    and escalates to an incident and UiPath RPA containment if necessary.
    """
    agent = AegisAgent(db=db)
    trace = agent.investigate(
        url=payload.url,
        url_scan_id=payload.url_scan_id,
        depth=payload.depth,
        force_escalate=payload.force_escalate,
        client_ip=payload.client_ip,
        user_agent=payload.user_agent,
        redirect_chain=payload.redirect_chain,
        domain_age_days=payload.domain_age_days,
    )

    action_trace = [
        AgentActionTraceItem(
            action_type=step.action_type,
            tool_name=step.tool_name,
            tool_input=step.tool_input,
            tool_output=step.tool_output,
            decision_rationale=step.decision_rationale,
            status=step.status,
            timestamp=step.timestamp,
        )
        for step in trace.steps
    ]

    return InvestigateResponse(
        url=trace.url,
        url_scan_id=trace.url_scan_id,
        initial_risk_score=trace.initial_risk_score,
        final_risk_score=trace.final_risk_score,
        classification=trace.classification,
        decision=trace.decision,
        incident_created=trace.incident_created,
        incident_id=trace.incident_id,
        incident_number=trace.incident_number,
        evidence_collected=trace.evidence_collected,
        action_trace=action_trace,
        recommended_action=trace.recommended_action,
        verification_results=trace.verification_results,
    )

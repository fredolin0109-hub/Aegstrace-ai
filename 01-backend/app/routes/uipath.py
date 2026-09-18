from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.uipath import UiPathTriggerRequest, UiPathActionResponse, UiPathStatusResponse
from app.services.uipath_service import trigger_uipath_workflow, get_uipath_action_status

router = APIRouter(prefix="/uipath", tags=["UiPath RPA"])


@router.post("/trigger", response_model=UiPathActionResponse, status_code=status.HTTP_202_ACCEPTED, summary="Trigger an automated UiPath RPA security response")
def trigger_action(
    payload: UiPathTriggerRequest,
    db: Session = Depends(get_db)
):
    """
    Triggers an authorized UiPath response action for an incident.
    In DEMO_MODE, safely simulates containment, ticketing, and alerting actions.
    """
    valid_actions = {
        "CREATE_TICKET", "CONTAIN_HOST", "NOTIFY_SOC",
        "ISOLATE_USER", "GENERATE_REPORT", "BLOCK_DOMAIN"
    }
    if payload.action_type not in valid_actions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action_type '{payload.action_type}'. Must be one of: {', '.join(sorted(valid_actions))}"
        )

    try:
        action = trigger_uipath_workflow(db=db, request=payload, actor="SOC_API")
        return UiPathActionResponse(
            id=action.id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            execution_id=action.execution_id,
            status=action.status,
            input_payload=action.input_payload_json or {},
            result_payload=action.result_payload_json,
            error_message=action.error_message,
            executed_at=action.executed_at,
            completed_at=action.completed_at,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"UiPath trigger failed: {str(e)}")


@router.get("/status/{execution_id}", response_model=UiPathStatusResponse, summary="Get status and telemetry of a UiPath RPA execution")
def get_status(
    execution_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves live execution status, logs, and output payload from a UiPath job."""
    action_info = get_uipath_action_status(db=db, execution_id=execution_id)
    if not action_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"UiPath execution with ID '{execution_id}' was not found"
        )

    return UiPathStatusResponse(
        execution_id=action_info["execution_id"],
        incident_id=action_info["incident_id"],
        action_type=action_info["action_type"],
        status=action_info["status"],
        progress_percentage=action_info["progress_percentage"],
        executed_at=action_info["executed_at"],
        completed_at=action_info["completed_at"],
        result=action_info["result"],
        error_message=action_info["error_message"],
        is_simulation=action_info["is_simulation"],
    )

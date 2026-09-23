"""
AEGISTRACE Risk Alert & Automation Routes
Exposes endpoints for risk alert intake, UiPath webhook callbacks, and automation retries.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.risk_alert import (
    RiskAlertRequest,
    RiskAlertResponse,
    UiPathCallbackRequest,
    UiPathCallbackResponse,
    RetryAlertRequest,
)
from app.services.risk_alert_service import (
    process_risk_alert,
    process_uipath_callback,
    retry_incident_automation,
)

router = APIRouter(tags=["Risk Automation & UiPath"])


@router.post(
    "/risk-alert",
    response_model=RiskAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest risk alert, trigger UiPath RPA and dispatch automated security email",
)
def handle_risk_alert(
    payload: RiskAlertRequest,
    db: Session = Depends(get_db),
):
    """
    Intake for high-risk and suspicious URL detections:
    - Validates URL and risk score
    - Categorizes into LOW (0-29), MEDIUM (30-69), or HIGH (70-100)
    - Automatically provisions or updates incident records
    - Dispatches UiPath RPA workflow and priority security email alerts for HIGH risk
    - Returns structured automation status and execution telemetry
    """
    try:
        response = process_risk_alert(db=db, payload=payload)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process risk alert: {str(e)}",
        )


@router.post(
    "/uipath/callback",
    response_model=UiPathCallbackResponse,
    status_code=status.HTTP_200_OK,
    summary="Receive execution confirmation callback from UiPath robot",
)
def handle_callback(
    payload: UiPathCallbackRequest,
    db: Session = Depends(get_db),
):
    """
    Callback endpoint triggered by UiPath Orchestrator or robots:
    - Updates execution status in uipath_actions
    - Confirms email delivery status
    - Updates incident progress and appends immutable audit records
    """
    try:
        response = process_uipath_callback(db=db, payload=payload)
        return response
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Callback processing error: {str(e)}",
        )


@router.post(
    "/uipath/retry",
    status_code=status.HTTP_200_OK,
    summary="Retry failed or unconfirmed UiPath or email automation for an incident",
)
def handle_retry(
    payload: RetryAlertRequest,
    db: Session = Depends(get_db),
):
    """
    Idempotent retry mechanism allowing SOC analysts to retry:
    - UiPath robotic workflow dispatch
    - Security alert email delivery
    - Or all automations simultaneously
    """
    try:
        result = retry_incident_automation(db=db, payload=payload)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Automation retry failed: {str(e)}",
        )

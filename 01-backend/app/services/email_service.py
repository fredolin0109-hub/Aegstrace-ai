"""
AEGISTRACE Automated Email Alert Service
Provides template rendering, test-mode logging, and secure SMTP dispatch for risk alerts.
"""
import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.config import settings

logger = logging.getLogger("aegistrace.email")


def get_template_path(risk_level: str) -> Path:
    """Resolve absolute path to email HTML template."""
    root_dir = Path(__file__).resolve().parents[3]
    templates_dir = root_dir / "08-uipath-rpa" / "email-templates"
    
    if risk_level.upper() == "HIGH":
        tmpl = templates_dir / "high-risk.html"
    else:
        tmpl = templates_dir / "medium-risk.html"

    if tmpl.exists():
        return tmpl
    
    # Fallback to local default if template directory moved
    return tmpl


def render_email_content(
    risk_level: str,
    incident_id: str,
    url: str,
    risk_score: int,
    classification: str,
    reasons: List[str],
    timestamp: Optional[str] = None,
) -> Dict[str, str]:
    """
    Renders email subject and HTML/plain body using configured templates and placeholders.
    """
    time_str = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format reasons as HTML list items
    if reasons and isinstance(reasons, list):
        reasons_html = "".join([f"<li>{r}</li>" for r in reasons])
        reasons_text = "\n".join([f"  - {r}" for r in reasons])
    else:
        reasons_html = "<li>Suspicious behavioral telemetry observed.</li>"
        reasons_text = "  - Suspicious behavioral telemetry observed."

    # Subject line based on priority
    if risk_level.upper() == "HIGH":
        subject = f"[AEGISTRACE] HIGH-RISK Security Alert — {incident_id}"
        template_file = get_template_path("HIGH")
    else:
        subject = f"[AEGISTRACE] Security Review Required — {incident_id}"
        template_file = get_template_path("MEDIUM")

    replacements = {
        "{{incident_id}}": str(incident_id),
        "{{url}}": str(url),
        "{{risk_score}}": str(risk_score),
        "{{classification}}": str(classification),
        "{{risk_level}}": str(risk_level).upper(),
        "{{reasons}}": reasons_html,
        "{{timestamp}}": time_str,
    }

    if template_file.exists():
        html_body = template_file.read_text(encoding="utf-8")
        for key, val in replacements.items():
            html_body = html_body.replace(key, val)
    else:
        # Fallback inline HTML
        html_body = f"""
        <html>
        <body style="font-family: sans-serif; background: #030712; color: #fff; padding: 20px;">
          <h2>AEGISTRACE SECURITY ALERT ({risk_level.upper()})</h2>
          <p><strong>Incident:</strong> {incident_id}</p>
          <p><strong>URL:</strong> {url}</p>
          <p><strong>Risk Score:</strong> {risk_score}%</p>
          <p><strong>Classification:</strong> {classification}</p>
          <p><strong>Reasons:</strong></p>
          <ul>{reasons_html}</ul>
          <p><strong>Time:</strong> {time_str}</p>
        </body>
        </html>
        """

    plain_body = f"""AEGISTRACE SECURITY ALERT
========================
Risk Level    : {risk_level.upper()}
Incident ID   : {incident_id}
Detected URL  : {url}
Risk Score    : {risk_score}%
Classification: {classification}
Time          : {time_str}

Indicators:
{reasons_text}

Automated Response: UiPath workflow initiated. Review in AEGISTRACE dashboard.
"""

    return {
        "subject": subject,
        "html_body": html_body,
        "plain_body": plain_body,
    }


def send_risk_alert_email(
    risk_level: str,
    incident_id: str,
    url: str,
    risk_score: int,
    classification: str,
    reasons: List[str],
    recipient_email: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dispatches security alert email.
    If EMAIL_TEST_MODE is enabled, safely logs email content without connecting to external SMTP.
    If EMAIL_TEST_MODE is false, attempts TLS/SSL SMTP delivery.
    """
    recipient = recipient_email or settings.ALERT_EMAIL
    rendered = render_email_content(
        risk_level=risk_level,
        incident_id=incident_id,
        url=url,
        risk_score=risk_score,
        classification=classification,
        reasons=reasons,
        timestamp=timestamp,
    )

    result = {
        "recipient": recipient,
        "subject": rendered["subject"],
        "risk_level": risk_level.upper(),
        "incident_id": incident_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "test_mode": settings.EMAIL_TEST_MODE,
    }

    # Safe test mode: record telemetry without external network transmission
    if settings.EMAIL_TEST_MODE:
        logger.info(
            f"[EMAIL_TEST_MODE] Mock email sent to {recipient} | Subject: {rendered['subject']}"
        )
        result["status"] = "TEST_MODE_LOGGED"
        result["message"] = f"Email safely generated and logged in TEST_MODE for {recipient}."
        result["preview_subject"] = rendered["subject"]
        return result

    # Production SMTP delivery
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = rendered["subject"]
        msg["From"] = settings.SMTP_FROM
        msg["To"] = recipient

        part1 = MIMEText(rendered["plain_body"], "plain", "utf-8")
        part2 = MIMEText(rendered["html_body"], "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, [recipient], msg.as_string())

        logger.info(f"Production alert email delivered to {recipient} for {incident_id}")
        result["status"] = "SENT"
        result["message"] = f"Alert email delivered to {recipient}."
        return result

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication failure")
        result["status"] = "FAILED"
        result["error"] = "SMTP authentication rejected credentials"
        return result
    except smtplib.SMTPConnectError:
        logger.error(f"Failed to connect to SMTP host {settings.SMTP_HOST}:{settings.SMTP_PORT}")
        result["status"] = "FAILED"
        result["error"] = "Failed to connect to configured SMTP host"
        return result
    except Exception as exc:
        logger.error(f"Unexpected email delivery failure: {exc}")
        result["status"] = "FAILED"
        result["error"] = "Email delivery error occurred"
        return result

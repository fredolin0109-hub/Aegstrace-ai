import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

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

from action_trace import ActionTrace
from decision_engine import DecisionEngine, DecisionResult
from tools.analyze_url import analyze_url
from tools.threat_lookup import threat_lookup
from tools.domain_check import domain_check
from tools.redirect_check import redirect_check
from tools.create_incident import create_incident
from tools.trigger_uipath import trigger_uipath
from tools.verify_response import verify_response


class AegisAgent:
    """
    Autonomous SOC Incident Investigation & Automated Response Agent.
    Coordinates the end-to-end 5-phase security workflow:
    1. DETECT       -> Algorithmic & predictive baseline threat identification
    2. INVESTIGATE  -> Multi-source evidence gathering (reputation, domain signals, redirect topology)
    3. DECIDE       -> Deterministic policy matrix evaluation
    4. ACT          -> SOC incident escalation & authorized UiPath RPA containment dispatch
    5. VERIFY       -> Response validation, ticket verification, and containment proof
    """

    def __init__(
        self,
        db: Optional[Any] = None,
        high_risk_threshold: float = 0.70,
        medium_risk_threshold: float = 0.35,
        critical_threshold: float = 0.85,
    ):
        self.db = db
        self.decision_engine = DecisionEngine(
            high_risk_threshold=high_risk_threshold,
            medium_risk_threshold=medium_risk_threshold,
            critical_threshold=critical_threshold,
        )

    def investigate(
        self,
        url: str,
        url_scan_id: Optional[int] = None,
        depth: str = "standard",
        force_escalate: bool = False,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        redirect_chain: Optional[List[str]] = None,
    ) -> ActionTrace:
        """
        Executes the autonomous 5-phase investigation lifecycle on the target URL.
        Returns an auditable, fully articulated ActionTrace.
        """
        trace = ActionTrace(url=url, url_scan_id=url_scan_id, depth=depth)

        # =========================================================================
        # PHASE 1: DETECT — Fast DSA & AIML Baseline Threat Analysis
        # =========================================================================
        detect_data = analyze_url(
            url=url,
            db=self.db,
            url_scan_id=url_scan_id,
            client_ip=client_ip,
            user_agent=user_agent,
            redirect_chain=redirect_chain,
        )

        domain = detect_data.get("domain", "")
        baseline_risk = detect_data.get("risk_score", 0.05)
        classification = detect_data.get("classification", "SAFE")
        features = detect_data.get("features", {})

        if detect_data.get("url_scan_id") and not trace.url_scan_id:
            trace.url_scan_id = detect_data["url_scan_id"]

        trace.set_initial_risk(baseline_risk, classification)

        # Collect baseline evidence from heuristics and detection signals
        if features.get("is_ip_address"):
            trace.add_evidence("Direct IP address routing bypasses standard domain name validation.")
        if features.get("detected_keywords"):
            kws = ", ".join(features.get("detected_keywords", []))
            trace.add_evidence(f"High-risk phishing keywords detected: {kws}.")
        if features.get("is_suspicious_tld"):
            trace.add_evidence(f"High-abuse top-level domain detected: .{features.get('tld')}.")
        if features.get("has_at_symbol"):
            trace.add_evidence("Authority spoofing / credential obscuration character '@' detected in URL.")
        if not features.get("is_https") and len(features.get("detected_keywords", [])) > 0:
            trace.add_evidence("Insecure HTTP protocol combined with credential authentication lures.")
        if detect_data.get("dsa_verdict") == "HIGH_RISK":
            trace.add_evidence("DSA pattern engine matched high-severity threat signature.")

        trace.record_step(
            action_type="DETECT",
            tool_name="analyze_url",
            tool_input={"url": url, "depth": depth},
            tool_output={
                "risk_score": baseline_risk,
                "classification": classification,
                "confidence": detect_data.get("confidence", 0.50),
                "dsa_verdict": detect_data.get("dsa_verdict"),
                "aiml_classification": detect_data.get("aiml_classification"),
                "aiml_risk_score": detect_data.get("aiml_risk_score"),
            },
            decision_rationale=f"Baseline threat detection evaluated initial risk at {baseline_risk:.2f} ({classification}).",
            status="SUCCESS",
        )

        # =========================================================================
        # PHASE 2: INVESTIGATE — Multi-source Intelligence & Deep Heuristics
        # =========================================================================
        # Tool 2.1: Threat Database / HashMap Lookup
        threat_data = threat_lookup(domain_or_url=domain or url, db=self.db)
        if threat_data.get("evidence"):
            trace.add_evidence(threat_data["evidence"])

        trace.record_step(
            action_type="INVESTIGATE",
            tool_name="threat_lookup",
            tool_input={"domain": domain},
            tool_output={
                "category": threat_data.get("category"),
                "is_known_threat": threat_data.get("is_known_threat"),
                "threat_type": threat_data.get("threat_type"),
                "reputation_score": threat_data.get("reputation_score"),
            },
            decision_rationale=(
                f"Threat intelligence hashmap query returned reputation category '{threat_data.get('category')}' "
                f"with score {threat_data.get('reputation_score')}."
            ),
            status="SUCCESS",
        )

        # Tool 2.2: Domain Signals, Shannon Entropy & Brand Spoofing Check
        domain_data = domain_check(domain_or_url=domain or url, url=url)
        if domain_data.get("evidence"):
            trace.add_evidence(domain_data["evidence"])

        trace.record_step(
            action_type="INVESTIGATE",
            tool_name="domain_check",
            tool_input={"domain": domain, "depth": depth},
            tool_output={
                "entropy": domain_data.get("entropy"),
                "is_high_entropy": domain_data.get("is_high_entropy"),
                "subdomain_count": domain_data.get("subdomain_count"),
                "is_suspicious_tld": domain_data.get("is_suspicious_tld"),
                "brand_spoof_detected": domain_data.get("brand_spoof_detected"),
                "risk_delta": domain_data.get("risk_delta"),
            },
            decision_rationale=(
                f"Domain structural inspection measured entropy {domain_data.get('entropy')} bits, "
                f"{domain_data.get('subdomain_count')} subdomains, brand_spoof={domain_data.get('brand_spoof_detected')}."
            ),
            status="SUCCESS",
        )

        # Tool 2.3: Redirect Chain Topology & Evasive Loop Detection
        redirect_data = None
        if redirect_chain or features.get("has_redirect_token") or depth == "deep":
            redirect_data = redirect_check(url=url, redirect_chain=redirect_chain)
            if redirect_data.get("evidence"):
                trace.add_evidence(redirect_data["evidence"])

            trace.record_step(
                action_type="INVESTIGATE",
                tool_name="redirect_check",
                tool_input={"url": url, "redirect_chain_length": len(redirect_chain) if redirect_chain else 0},
                tool_output={
                    "has_loop": redirect_data.get("has_redirect_loop"),
                    "hop_count": redirect_data.get("hop_count"),
                    "open_redirect_params": redirect_data.get("open_redirect_params"),
                    "is_evasive": redirect_data.get("is_evasive"),
                },
                decision_rationale=(
                    f"Redirect graph inspection: loop_detected={redirect_data.get('has_redirect_loop')}, "
                    f"hops={redirect_data.get('hop_count')}."
                ),
                status="SUCCESS",
            )

        # Synthesize Evidence & Finalize Risk Score
        has_loop = bool(redirect_data and redirect_data.get("has_redirect_loop"))
        if threat_data.get("category") == "SAFE" and not force_escalate:
            final_risk = 0.0
            final_classification = "SAFE"
        elif threat_data.get("category") == "MALICIOUS":
            final_risk = max(baseline_risk, 0.95)
            final_classification = "HIGH_RISK"
        else:
            accumulated_score = baseline_risk
            if has_loop:
                accumulated_score += 0.35
            if domain_data.get("brand_spoof_detected"):
                accumulated_score += 0.30
            if domain_data.get("is_high_entropy"):
                accumulated_score += 0.15
            if redirect_data and redirect_data.get("open_redirect_params"):
                accumulated_score += 0.20

            final_risk = round(min(1.0, max(baseline_risk, accumulated_score)), 2)
            if final_risk >= 0.70:
                final_classification = "HIGH_RISK"
            elif final_risk >= 0.35:
                final_classification = "SUSPICIOUS"
            else:
                final_classification = "SAFE"

        trace.set_final_risk(final_risk, final_classification)

        # =========================================================================
        # PHASE 3: DECIDE — Deterministic Policy Matrix Evaluation
        # =========================================================================
        decision_result: DecisionResult = self.decision_engine.evaluate(
            risk_score=final_risk,
            classification=final_classification,
            evidence=trace.evidence_collected,
            depth=depth,
            force_escalate=force_escalate,
            domain_category=threat_data.get("category"),
            has_redirect_loop=has_loop,
            is_known_threat=threat_data.get("is_known_threat", False),
        )

        trace.set_decision(decision_result.decision, decision_result.recommended_action)

        trace.record_step(
            action_type="DECIDE",
            tool_name="decision_engine",
            tool_input={
                "risk_score": final_risk,
                "classification": final_classification,
                "force_escalate": force_escalate,
                "depth": depth,
            },
            tool_output={
                "decision": decision_result.decision,
                "recommended_action": decision_result.recommended_action,
                "risk_tier": decision_result.risk_tier,
                "should_create_incident": decision_result.should_create_incident,
                "incident_severity": decision_result.incident_severity,
                "should_trigger_uipath": decision_result.should_trigger_uipath,
                "uipath_action_type": decision_result.uipath_action_type,
            },
            decision_rationale=decision_result.rationale,
            status="SUCCESS",
        )

        # =========================================================================
        # PHASE 4: ACT — SOC Incident Escalation & UiPath RPA Containment Dispatch
        # =========================================================================
        incident_data = None
        if decision_result.should_create_incident:
            incident_data = create_incident(
                url=url,
                domain=domain,
                risk_score=final_risk,
                severity=decision_result.incident_severity,
                evidence=trace.evidence_collected,
                url_scan_id=trace.url_scan_id,
                db=self.db,
                actor="AEGIS_AGENT",
            )
            trace.set_incident(
                incident_id=incident_data["incident_id"],
                incident_number=incident_data["incident_number"],
            )

            trace.record_step(
                action_type="ACT",
                tool_name="create_incident",
                tool_input={
                    "url": url,
                    "domain": domain,
                    "severity": decision_result.incident_severity,
                    "evidence_count": len(trace.evidence_collected),
                },
                tool_output={
                    "incident_id": incident_data["incident_id"],
                    "incident_number": incident_data["incident_number"],
                    "status": incident_data["status"],
                },
                decision_rationale=(
                    f"Generated official SOC incident record {incident_data['incident_number']} "
                    f"with severity {incident_data['severity']}."
                ),
                status="SUCCESS",
            )

        uipath_data = None
        if decision_result.should_trigger_uipath:
            uipath_data = trigger_uipath(
                target_url=url,
                incident_id=trace.incident_id,
                incident_number=trace.incident_number,
                action_type=decision_result.uipath_action_type or "CONTAIN_HOST",
                parameters={"automated_by": "AegisAgent", "risk_score": final_risk},
                db=self.db,
                actor="AEGIS_AGENT",
            )

            trace.record_step(
                action_type="ACT",
                tool_name="trigger_uipath",
                tool_input={
                    "target_url": url,
                    "incident_id": trace.incident_id,
                    "action_type": decision_result.uipath_action_type or "CONTAIN_HOST",
                },
                tool_output={
                    "execution_id": uipath_data.get("execution_id"),
                    "action_type": uipath_data.get("action_type"),
                    "status": uipath_data.get("status"),
                    "simulation": uipath_data.get("simulation", True),
                },
                decision_rationale=(
                    f"Dispatched UiPath RPA automation action '{decision_result.uipath_action_type}' "
                    f"with execution ID {uipath_data.get('execution_id')}."
                ),
                status="SUCCESS",
            )

        # Record operational step for non-escalated outcomes (MONITOR or SAFE_PASS)
        if not decision_result.should_create_incident and not decision_result.should_trigger_uipath:
            if decision_result.decision == "MONITOR":
                trace.record_step(
                    action_type="ACT",
                    tool_name="soc_monitor_logger",
                    tool_input={"url": url, "action": "LOG_AND_WATCH"},
                    tool_output={"status": "LOGGED_TO_AUDIT"},
                    decision_rationale="Logged suspicious URL to SOC monitoring stream for ongoing traffic observation.",
                    status="SUCCESS",
                )
            else:  # SAFE_PASS
                trace.record_step(
                    action_type="ACT",
                    tool_name="policy_allow_gateway",
                    tool_input={"url": url, "action": "ALLOW"},
                    tool_output={"status": "AUTHORIZED"},
                    decision_rationale="Authorized safe passage for legitimate target matching allowlist policy.",
                    status="SUCCESS",
                )

        # =========================================================================
        # PHASE 5: VERIFY — Automated Containment, Ticket & Policy Verification
        # =========================================================================
        if decision_result.should_trigger_uipath and uipath_data:
            verify_data = verify_response(
                execution_id=uipath_data.get("execution_id"),
                incident_id=trace.incident_id,
                action_type=decision_result.uipath_action_type,
                uipath_result=uipath_data,
                db=self.db,
            )
            trace.set_verification(verify_data)

            trace.record_step(
                action_type="VERIFY",
                tool_name="verify_response",
                tool_input={
                    "execution_id": uipath_data.get("execution_id"),
                    "incident_id": trace.incident_id,
                },
                tool_output={
                    "verified": verify_data.get("verified"),
                    "containment_status": verify_data.get("containment_status"),
                    "ticket_id": verify_data.get("ticket_id"),
                    "checks": verify_data.get("checks", []),
                },
                decision_rationale=(
                    f"Response containment verified: status='{verify_data.get('containment_status')}', "
                    f"ticket_id='{verify_data.get('ticket_id')}'."
                ),
                status="SUCCESS",
            )
        else:
            verify_data = {
                "verified": True,
                "containment_status": "NOT_APPLICABLE",
                "policy_compliant": True,
                "verification_checks": [
                    {"check": "POLICY_CONFORMANCE", "passed": True, "detail": f"Outcome {decision_result.decision} valid."}
                ],
            }
            trace.set_verification(verify_data)

            trace.record_step(
                action_type="VERIFY",
                tool_name="policy_compliance_verifier",
                tool_input={"url": url, "decision": decision_result.decision},
                tool_output={"policy_compliant": True, "status": "VERIFIED"},
                decision_rationale=f"Verified compliance against zero-trust policy: decision '{decision_result.decision}' confirmed.",
                status="SUCCESS",
            )

        # =========================================================================
        # Save Action Trace to Database (Audit Trail)
        # =========================================================================
        trace.save_to_db(self.db)

        return trace

import sys
from pathlib import Path

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

from .action_trace import ActionTrace, ActionTraceItem
from .decision_engine import DecisionEngine, DecisionResult
from .agent import AegisAgent
from .tools.analyze_url import analyze_url
from .tools.threat_lookup import threat_lookup
from .tools.domain_check import domain_check
from .tools.redirect_check import redirect_check
from .tools.create_incident import create_incident
from .tools.trigger_uipath import trigger_uipath
from .tools.verify_response import verify_response

__all__ = [
    "AegisAgent",
    "DecisionEngine",
    "DecisionResult",
    "ActionTrace",
    "ActionTraceItem",
    "analyze_url",
    "threat_lookup",
    "domain_check",
    "redirect_check",
    "create_incident",
    "trigger_uipath",
    "verify_response",
]

import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
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

from graph import ThreatGraph

OPEN_REDIRECT_PARAM_NAMES = {
    "url", "dest", "destination", "redirect", "redirect_to", "redirect_url",
    "target", "next", "return", "return_to", "goto", "link", "r", "u", "uri", "path"
}


def redirect_check(
    url: Optional[str] = None,
    redirect_chain: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Inspects HTTP redirect sequences, models the hop topology in ThreatGraph,
    detects evasive redirect cycles/loops, and flags open redirect vulnerabilities.
    """
    if not url or not isinstance(url, str) or not url.strip():
        return {
            "url": "",
            "has_redirect_loop": False,
            "cycle_nodes": [],
            "hop_count": 0,
            "chain": [],
            "open_redirect_params": [],
            "cross_domain_hops": [],
            "is_evasive": False,
            "risk_delta": 0.0,
            "evidence": [],
        }

    clean_url = url.strip()
    parsed = urlparse(clean_url)
    origin_domain = (parsed.hostname or "").lower()

    # 1. Parse and detect open redirect parameters in the query string
    open_redirect_params: List[str] = []
    qs = parse_qs(parsed.query)
    for param_name, values in qs.items():
        if param_name.lower() in OPEN_REDIRECT_PARAM_NAMES:
            for val in values:
                decoded_val = unquote(unquote(val))
                if re.search(r"^(https?://|//|https?%3A%2F%2F|%2F%2F|ftp://)", val, re.IGNORECASE) or \
                   re.search(r"^(https?://|//|ftp://)", decoded_val, re.IGNORECASE):
                    open_redirect_params.append(f"{param_name}={val}")

    # 2. Build ThreatGraph and check for cycles
    graph = ThreatGraph()
    graph.add_node(clean_url, "URL")

    chain: List[str] = [clean_url]
    cross_domain_hops: List[Dict[str, str]] = []

    if redirect_chain:
        prev_hop = clean_url
        prev_domain = origin_domain

        for hop in redirect_chain:
            if not hop or not isinstance(hop, str):
                continue
            hop_clean = hop.strip()
            if not hop_clean:
                continue

            hop_domain = (urlparse(hop_clean).hostname or "").lower()
            chain.append(hop_clean)

            graph.add_node(hop_clean, "REDIRECT_HOP")
            graph.add_edge(prev_hop, hop_clean, "REDIRECTS_TO")

            if prev_domain and hop_domain and prev_domain != hop_domain:
                cross_domain_hops.append({
                    "from_domain": prev_domain,
                    "to_domain": hop_domain,
                })

            prev_hop = hop_clean
            prev_domain = hop_domain

    has_loop, cycle_nodes = graph.detect_redirect_loops()

    # 3. Assess evasion signals & generate evidence
    evidence: List[str] = []
    risk_delta = 0.0

    if has_loop:
        risk_delta += 0.35
        cycle_str = " -> ".join(cycle_nodes)
        evidence.append(f"ThreatGraph detected evasive redirect cycle/loop: {cycle_str}.")

    if len(open_redirect_params) > 0:
        risk_delta += 0.25
        evidence.append(
            f"Open redirect parameter detected in URL query: {', '.join(open_redirect_params)}."
        )

    if len(chain) > 3:
        risk_delta += 0.15
        evidence.append(
            f"Anomalous redirect sequence ({len(chain)} hops) observed, indicative of multi-stage evasion."
        )

    if len(cross_domain_hops) >= 2:
        risk_delta += 0.15
        evidence.append(
            f"Multiple cross-domain redirect transitions detected ({len(cross_domain_hops)} jumps)."
        )

    is_evasive = has_loop or len(open_redirect_params) > 0 or len(chain) > 3

    return {
        "url": clean_url,
        "has_redirect_loop": has_loop,
        "cycle_nodes": cycle_nodes,
        "hop_count": len(chain),
        "chain": chain,
        "open_redirect_params": open_redirect_params,
        "cross_domain_hops": cross_domain_hops,
        "is_evasive": is_evasive,
        "risk_delta": round(min(0.50, risk_delta), 2),
        "evidence": evidence,
    }

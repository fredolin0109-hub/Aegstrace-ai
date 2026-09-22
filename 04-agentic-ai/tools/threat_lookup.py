import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

# Ensure repo root and submodules are in sys.path
_curr = Path(__file__).resolve()
while _curr.parent != _curr:
    if (_curr / "01-backend").exists() and (_curr / "02-dsa-engine").exists():
        for sub in ["01-backend", "02-dsa-engine", "03-aiml-engine", "03-aiml-engine/src", "04-agentic-ai", "05-threat-intelligence"]:
            sp = _curr / sub
            if sp.exists() and str(sp) not in sys.path:
                sys.path.insert(0, str(sp))
        break
    _curr = _curr.parent

from engine import global_dsa_engine
from hashmap import DomainEntry

try:
    from aggregator import global_threat_aggregator
except ImportError:
    global_threat_aggregator = None


def threat_lookup(
    domain_or_url: Optional[str] = None,
    db: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Checks the local high-performance DSA threat database and hashmap for known domain reputation.
    Supports parent domain decomposition and optional backend threat indicator correlation.
    """
    if not domain_or_url or not isinstance(domain_or_url, str) or not domain_or_url.strip():
        return {
            "domain": "",
            "is_known_threat": False,
            "category": "UNKNOWN",
            "threat_type": None,
            "reputation_score": 0.50,
            "metadata": {},
            "evidence": [],
            "db_indicators": [],
        }

    # Clean domain
    raw = domain_or_url.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        domain = parsed.hostname or raw
    else:
        domain = raw.split("/")[0].split(":")[0]

    domain_clean = domain.strip().lower()

    # 1. Lookup in DSA Threat Domain HashMap with parent fallback
    hmap = global_dsa_engine.domain_hashmap
    entry: Optional[DomainEntry] = hmap.get(domain_clean)

    if not entry and "." in domain_clean:
        parts = domain_clean.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            entry = hmap.get(parent)
            if entry:
                break

    evidence: List[str] = []
    is_known_threat = False
    category = "UNKNOWN"
    threat_type = None
    reputation_score = 0.50
    metadata: Dict[str, Any] = {}

    if entry:
        category = entry.category
        threat_type = entry.threat_type
        reputation_score = entry.reputation_score
        metadata = entry.metadata or {}

        if category == "MALICIOUS":
            is_known_threat = True
            desc = metadata.get("description", "Identified malicious entity")
            evidence.append(
                f"DSA Threat HashMap match: Known malicious domain '{entry.domain}' ({threat_type}). {desc}"
            )
        elif category == "SUSPICIOUS":
            is_known_threat = True
            desc = metadata.get("description", "Identified suspicious entity")
            evidence.append(
                f"DSA Threat HashMap match: Suspicious reputation for '{entry.domain}' ({threat_type}). {desc}"
            )
        elif category == "SAFE":
            is_known_threat = False
            desc = metadata.get("description", "Trusted domain")
            evidence.append(
                f"Enterprise allowlist match: Domain '{entry.domain}' verified safe. {desc}"
            )

    # 2. Check DB Threat Indicators if active DB session is supplied
    db_indicators = []
    if db is not None and domain_clean:
        try:
            from app.models.threat_indicator import ThreatIndicator
            records = db.query(ThreatIndicator).filter(
                ThreatIndicator.value.ilike(f"%{domain_clean}%")
            ).limit(5).all()

            for rec in records:
                db_indicators.append({
                    "indicator_type": rec.indicator_type,
                    "severity": rec.severity,
                    "value": rec.value,
                })
                if rec.severity in ("HIGH", "CRITICAL"):
                    is_known_threat = True
                    evidence.append(
                        f"Database threat indicator: {rec.indicator_type} ({rec.severity}) linked to {rec.value}."
                    )
        except Exception:
            pass

    # 3. Query Multi-Source Threat Intelligence Aggregator (Phase 5)
    threat_intel_data = None
    if global_threat_aggregator and domain_clean:
        try:
            report = global_threat_aggregator.lookup(domain_clean, target_type="domain")
            threat_intel_data = report.to_dict()

            if report.verdict in ("HIGH_RISK", "SUSPICIOUS") and not is_known_threat:
                is_known_threat = True
                category = "MALICIOUS" if report.verdict == "HIGH_RISK" else "SUSPICIOUS"
                threat_type = threat_type or "THREAT_INTEL_FLAG"
                active_sources = report.sources_available or report.sources_consulted
                evidence.append(
                    f"Multi-source Threat Intel: {report.verdict} (risk={report.composite_score:.2f}) verified by {', '.join(active_sources)}."
                )
        except Exception:
            pass

    return {
        "domain": domain_clean,
        "is_known_threat": is_known_threat,
        "category": category,
        "threat_type": threat_type,
        "reputation_score": reputation_score,
        "metadata": metadata,
        "evidence": evidence,
        "db_indicators": db_indicators,
        "threat_intel": threat_intel_data,
    }

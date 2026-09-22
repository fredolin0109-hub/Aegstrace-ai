from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from hashmap import ThreatDomainHashMap, create_default_threat_hashmap, DomainEntry
from trie import SuspiciousPatternTrie, create_default_pattern_trie, TrieMatch
from graph import ThreatGraph
from priority_queue import IncidentPriorityQueue
from searching import IncidentInvertedIndex, binary_search_domain
from sorting import quicksort_threat_scores, mergesort_incidents


@dataclass
class DSAScanResult:
    dsa_risk_score: float
    dsa_verdict: str
    known_domain_match: Optional[Dict[str, Any]]
    trie_matches: List[Dict[str, Any]]
    graph_summary: Dict[str, Any]
    detected_indicators: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DSAEngine:
    """
    Unified Data Structures & Algorithms (DSA) Engine for AEGISTRACE.
    Orchestrates HashMap, Trie, Graph, Priority Queue, Search, and Sort algorithms.
    """

    def __init__(self):
        self.domain_hashmap: ThreatDomainHashMap = create_default_threat_hashmap()
        self.pattern_trie: SuspiciousPatternTrie = create_default_pattern_trie()
        self.incident_queue: IncidentPriorityQueue = IncidentPriorityQueue()
        self.inverted_index: IncidentInvertedIndex = IncidentInvertedIndex()

    def analyze_url_dsa(
        self,
        raw_url: str,
        domain: str,
        ip_address: Optional[str] = None,
        redirect_chain: Optional[List[str]] = None,
    ) -> DSAScanResult:
        """
        Executes DSA inspection pipeline:
        1. O(1) HashMap lookup for domain reputation with robust parent domain fallback
        2. O(L) Trie multi-token substring search for phishing lures
        3. ThreatGraph topology modeling & cycle detection
        """
        score = 0.05
        indicators = []

        # 1. HashMap Domain Lookup
        domain_clean = domain.lower().strip()
        domain_entry: Optional[DomainEntry] = self.domain_hashmap.get(domain_clean)
        if not domain_entry and "." in domain_clean:
            parts = domain_clean.split(".")
            # Check parent domains from longest to shortest (at least 2 segments)
            for i in range(1, len(parts) - 1):
                parent_candidate = ".".join(parts[i:])
                domain_entry = self.domain_hashmap.get(parent_candidate)
                if domain_entry:
                    break
        known_match_data = None

        if domain_entry:
            known_match_data = {
                "domain": domain_entry.domain,
                "category": domain_entry.category,
                "reputation_score": domain_entry.reputation_score,
                "threat_type": domain_entry.threat_type,
                "metadata": domain_entry.metadata,
            }

            if domain_entry.category == "SAFE":
                # Known trusted domain drastically diminishes risk
                score = 0.0
                indicators.append({
                    "indicator_type": "KNOWN_LEGITIMATE_DOMAIN",
                    "value": domain,
                    "severity": "LOW",
                    "details": {"source": "DSA HashMap", "reputation": "SAFE"}
                })
            elif domain_entry.category == "MALICIOUS":
                score = max(score, domain_entry.reputation_score)
                indicators.append({
                    "indicator_type": "KNOWN_MALICIOUS_DOMAIN",
                    "value": domain,
                    "severity": "CRITICAL",
                    "details": {
                        "threat_type": domain_entry.threat_type,
                        "source": "DSA HashMap",
                        "description": domain_entry.metadata.get("description", "Identified malicious host")
                    }
                })
            elif domain_entry.category == "SUSPICIOUS":
                score = max(score, domain_entry.reputation_score)
                indicators.append({
                    "indicator_type": "KNOWN_SUSPICIOUS_DOMAIN",
                    "value": domain,
                    "severity": "HIGH",
                    "details": {
                        "threat_type": domain_entry.threat_type,
                        "source": "DSA HashMap",
                        "description": domain_entry.metadata.get("description", "Identified suspicious host")
                    }
                })

        # 2. Trie Pattern Scanning
        trie_matches: List[TrieMatch] = self.pattern_trie.scan_text(raw_url)
        trie_match_dicts = []

        if trie_matches:
            # Deduplicate by pattern to avoid multiplying weight on repeated occurrences
            unique_patterns: Dict[str, TrieMatch] = {}
            for m in trie_matches:
                if m.pattern not in unique_patterns or m.weight > unique_patterns[m.pattern].weight:
                    unique_patterns[m.pattern] = m

            trie_weight_sum = sum(m.weight for m in unique_patterns.values())
            score += min(0.45, trie_weight_sum)

            for m in trie_matches:
                match_dict = {
                    "pattern": m.pattern,
                    "category": m.category,
                    "severity": m.severity,
                    "weight": m.weight,
                    "span": [m.start_index, m.end_index],
                }
                trie_match_dicts.append(match_dict)

            for m in unique_patterns.values():
                indicators.append({
                    "indicator_type": f"TRIE_{m.category}",
                    "value": m.pattern,
                    "severity": m.severity,
                    "details": {"pattern": m.pattern, "category": m.category, "weight": m.weight}
                })

        # 3. ThreatGraph Construction & Analysis
        graph = ThreatGraph()
        graph.add_node(raw_url, "URL", risk_score=score)
        graph.add_node(domain, "DOMAIN", risk_score=score)
        graph.add_edge(raw_url, domain, "HOSTED_ON")

        if ip_address:
            graph.add_node(ip_address, "IP", risk_score=score)
            graph.add_edge(domain, ip_address, "RESOLVES_TO")

        # Ingest redirect chain if present
        if redirect_chain:
            prev_hop = raw_url
            for hop in redirect_chain:
                hop_clean = hop.strip()
                if hop_clean:
                    graph.add_node(hop_clean, "REDIRECT_HOP", risk_score=score)
                    graph.add_edge(prev_hop, hop_clean, "REDIRECTS_TO")
                    prev_hop = hop_clean

        has_loop, cycle_nodes = graph.detect_redirect_loops()
        if has_loop:
            score += 0.30
            indicators.append({
                "indicator_type": "GRAPH_REDIRECT_LOOP",
                "value": " -> ".join(cycle_nodes),
                "severity": "HIGH",
                "details": {"cycle": cycle_nodes}
            })

        graph_summary = {
            "total_nodes": len(graph.nodes),
            "total_edges": sum(len(e) for e in graph.adjacency.values()),
            "has_redirect_loop": has_loop,
            "chain": graph.trace_chain(raw_url),
        }

        final_dsa_score = round(min(1.0, max(0.0, score)), 2)

        if final_dsa_score >= 0.70:
            verdict = "HIGH_RISK"
        elif final_dsa_score >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return DSAScanResult(
            dsa_risk_score=final_dsa_score,
            dsa_verdict=verdict,
            known_domain_match=known_match_data,
            trie_matches=trie_match_dicts,
            graph_summary=graph_summary,
            detected_indicators=indicators,
        )


# Singleton instance for high-throughput reuse
global_dsa_engine = DSAEngine()

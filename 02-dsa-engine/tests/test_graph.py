import pytest
from graph import ThreatGraph


def test_threat_graph_nodes_and_edges():
    g = ThreatGraph()
    g.add_node("phish-gate.com", "DOMAIN", risk_score=0.4)
    g.add_node("192.0.2.1", "IP", risk_score=0.4)
    g.add_edge("phish-gate.com", "192.0.2.1", "RESOLVES_TO")

    assert len(g.nodes) == 2
    assert "phish-gate.com" in g.adjacency
    assert g.adjacency["phish-gate.com"][0].target_id == "192.0.2.1"


def test_threat_graph_redirect_loop_detection():
    g = ThreatGraph()
    # A -> B -> C -> A
    g.add_edge("domain-a.com", "domain-b.com", "REDIRECTS_TO")
    g.add_edge("domain-b.com", "domain-c.com", "REDIRECTS_TO")
    g.add_edge("domain-c.com", "domain-a.com", "REDIRECTS_TO")

    has_loop, cycle_nodes = g.detect_redirect_loops()
    assert has_loop is True
    assert len(cycle_nodes) >= 3


def test_threat_graph_acyclic_chain():
    g = ThreatGraph()
    # A -> B -> C -> D
    g.add_edge("entry.com", "shortener.link", "REDIRECTS_TO")
    g.add_edge("shortener.link", "tracker.io", "REDIRECTS_TO")
    g.add_edge("tracker.io", "target.xyz", "REDIRECTS_TO")

    has_loop, _ = g.detect_redirect_loops()
    assert has_loop is False

    chain = g.trace_chain("entry.com")
    assert len(chain) == 4
    assert chain[0]["id"] == "entry.com"
    assert chain[3]["id"] == "target.xyz"


def test_threat_graph_risk_propagation():
    g = ThreatGraph()
    # Malicious leaf D (risk 0.95)
    g.add_node("clean-hopping-domain.org", "DOMAIN", risk_score=0.0)
    g.add_node("shorturl.xyz", "DOMAIN", risk_score=0.1)
    g.add_node("malicious-landing.ru", "DOMAIN", risk_score=0.95)

    g.add_edge("clean-hopping-domain.org", "shorturl.xyz", "REDIRECTS_TO")
    g.add_edge("shorturl.xyz", "malicious-landing.ru", "REDIRECTS_TO")

    propagated = g.propagate_risk(decay_factor=0.8)
    assert propagated["malicious-landing.ru"] == 0.95
    # shorturl should inherit 0.95 * 0.8 = 0.76
    assert propagated["shorturl.xyz"] >= 0.70
    # clean hopping domain should inherit 0.76 * 0.8 = 0.608
    assert propagated["clean-hopping-domain.org"] >= 0.50

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque


@dataclass
class GraphNode:
    id: str
    node_type: str  # DOMAIN, IP, URL, REDIRECT_HOP
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # RESOLVES_TO, REDIRECTS_TO, HOSTED_ON, SERVES_SUBDOMAIN
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatGraph:
    """
    Directed graph representing entity topologies:
    Domain -> IP -> Redirect -> Target Domain.
    Implements cycle detection for redirect loops and risk propagation across network hops.
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[GraphEdge]] = {}
        self.reverse_adjacency: Dict[str, List[GraphEdge]] = {}

    def add_node(
        self,
        node_id: str,
        node_type: str,
        risk_score: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        """Add or update a vertex in the threat graph."""
        clean_id = node_id.strip()
        if clean_id not in self.nodes:
            node = GraphNode(
                id=clean_id,
                node_type=node_type.upper(),
                risk_score=max(0.0, min(1.0, risk_score)),
                metadata=metadata or {},
            )
            self.nodes[clean_id] = node
            self.adjacency[clean_id] = []
            self.reverse_adjacency[clean_id] = []
        else:
            node = self.nodes[clean_id]
            if risk_score > node.risk_score:
                node.risk_score = risk_score
            if metadata:
                node.metadata.update(metadata)
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str = "REDIRECTS_TO",
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        """Add directed relationship between two entities."""
        src = source_id.strip()
        dst = target_id.strip()

        if src not in self.nodes:
            self.add_node(src, "DOMAIN")
        if dst not in self.nodes:
            self.add_node(dst, "DOMAIN")

        edge = GraphEdge(
            source_id=src,
            target_id=dst,
            relationship=relationship.upper(),
            weight=weight,
            metadata=metadata or {},
        )
        self.adjacency[src].append(edge)
        self.reverse_adjacency[dst].append(edge)
        return edge

    def detect_redirect_loops(self) -> Tuple[bool, List[str]]:
        """
        Cycle detection algorithm using DFS with three-color vertex coloring.
        Returns: (has_loop, list_of_cycle_node_ids)
        """
        # 0: UNVISITED, 1: VISITING (in recursion stack), 2: VISITED
        visited: Dict[str, int] = {node_id: 0 for node_id in self.nodes}
        parent: Dict[str, Optional[str]] = {node_id: None for node_id in self.nodes}
        cycle: List[str] = []

        def dfs(u: str) -> bool:
            visited[u] = 1
            for edge in self.adjacency.get(u, []):
                v = edge.target_id
                if visited[v] == 1:
                    # Cycle detected: backtrack path
                    curr = u
                    cycle.append(v)
                    while curr != v and curr is not None:
                        cycle.append(curr)
                        curr = parent.get(curr)
                    cycle.reverse()
                    return True
                elif visited[v] == 0:
                    parent[v] = u
                    if dfs(v):
                        return True
            visited[u] = 2
            return False

        for node in self.nodes:
            if visited[node] == 0:
                if dfs(node):
                    return True, cycle

        return False, []

    def trace_chain(self, start_id: str, max_depth: int = 10) -> List[Dict[str, Any]]:
        """Trace downstream traversal from starting node via BFS."""
        clean_start = start_id.strip()
        if clean_start not in self.nodes:
            return []

        chain = []
        queue = deque([(clean_start, 0)])
        visited = {clean_start}

        while queue:
            curr_id, depth = queue.popleft()
            curr_node = self.nodes[curr_id]
            chain.append({
                "hop": depth,
                "id": curr_node.id,
                "type": curr_node.node_type,
                "risk_score": curr_node.risk_score,
            })

            if depth >= max_depth:
                continue

            for edge in self.adjacency.get(curr_id, []):
                nxt = edge.target_id
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, depth + 1))

        return chain

    def propagate_risk(self, decay_factor: float = 0.85) -> Dict[str, float]:
        """
        Propagates risk backwards through the graph.
        If a final redirect destination is malicious, upstream hopping nodes inherit decayed risk.
        """
        propagated_scores: Dict[str, float] = {nid: n.risk_score for nid, n in self.nodes.items()}

        # Order nodes by risk descending
        sorted_nodes = sorted(self.nodes.values(), key=lambda n: n.risk_score, reverse=True)

        for source in sorted_nodes:
            current_risk = propagated_scores[source.id]
            if current_risk <= 0.05:
                continue

            # Push risk backwards to nodes pointing to this node
            queue = deque([(source.id, current_risk)])
            visited = {source.id}

            while queue:
                curr_id, curr_score = queue.popleft()
                decayed = curr_score * decay_factor

                for rev_edge in self.reverse_adjacency.get(curr_id, []):
                    origin_id = rev_edge.source_id
                    if origin_id not in visited:
                        visited.add(origin_id)
                        if decayed > propagated_scores[origin_id]:
                            propagated_scores[origin_id] = round(decayed, 3)
                            self.nodes[origin_id].risk_score = propagated_scores[origin_id]
                            queue.append((origin_id, decayed))

        return propagated_scores

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary representation."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(e) for e in self.adjacency.values()),
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type,
                    "risk_score": n.risk_score,
                    "metadata": n.metadata
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relationship": e.relationship,
                    "weight": e.weight,
                }
                for edges in self.adjacency.values() for e in edges
            ],
        }

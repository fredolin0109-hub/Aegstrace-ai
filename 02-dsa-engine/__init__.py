"""
AEGISTRACE DSA Engine package.
Provides high-performance Data Structures & Algorithms for threat detection:
- ThreatDomainHashMap: O(1) domain reputation lookup
- SuspiciousPatternTrie: O(L) multi-token substring search
- ThreatGraph: Directed threat graph modeling & cycle detection
- IncidentPriorityQueue: Indexed Max-Heap for automated triage
- IncidentInvertedIndex & binary_search: Rapid query and search algorithms
- quicksort_threat_scores & mergesort_incidents: Optimized sorting routines
- DSAEngine: Unified facade pipeline
"""

from engine import DSAEngine, DSAScanResult, global_dsa_engine
from hashmap import ThreatDomainHashMap, DomainEntry, create_default_threat_hashmap
from trie import SuspiciousPatternTrie, TrieMatch, TrieNode, create_default_pattern_trie
from graph import ThreatGraph, GraphNode, GraphEdge
from priority_queue import IncidentPriorityQueue, IncidentPriorityItem
from searching import binary_search_domain, binary_search_ip_range, IncidentInvertedIndex
from sorting import quicksort_threat_scores, mergesort_incidents

__all__ = [
    "DSAEngine",
    "DSAScanResult",
    "global_dsa_engine",
    "ThreatDomainHashMap",
    "DomainEntry",
    "create_default_threat_hashmap",
    "SuspiciousPatternTrie",
    "TrieMatch",
    "TrieNode",
    "create_default_pattern_trie",
    "ThreatGraph",
    "GraphNode",
    "GraphEdge",
    "IncidentPriorityQueue",
    "IncidentPriorityItem",
    "binary_search_domain",
    "binary_search_ip_range",
    "IncidentInvertedIndex",
    "quicksort_threat_scores",
    "mergesort_incidents",
]

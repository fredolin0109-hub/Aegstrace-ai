# AEGISTRACE — DSA Engine (`02-dsa-engine`)

The **AEGISTRACE DSA Engine** provides ultra-fast, in-memory algorithmic components designed to process URL telemetry, detect evasive attack patterns, and prioritize incident triage in sub-millisecond execution times.

---

## Data Structures & Algorithms Overview

| Module | Data Structure / Algorithm | Time Complexity | Security Purpose |
|---|---|---|---|
| [`hashmap.py`](./hashmap.py) | Custom Hash Table (Chaining, Rolling Polynomial Hash) | $O(1)$ avg lookup | Instant reputation resolution for known safe & malicious domains |
| [`trie.py`](./trie.py) | Prefix & Substring Pattern Trie | $O(L)$ scanning | High-speed multi-token phishing keyword and lure detection |
| [`graph.py`](./graph.py) | Directed Threat Graph | $O(V + E)$ BFS/DFS | Models `Domain -> IP -> Redirect`, detects redirect loops & propagates risk |
| [`priority_queue.py`](./priority_queue.py) | Indexed Max-Heap | $O(\log N)$ push/pop | Automates SOC incident triage based on composite severity/risk |
| [`searching.py`](./searching.py) | Binary Search & Inverted Index | $O(\log N)$ / $O(K)$ | Fast domain prefix matching and full-text incident querying |
| [`sorting.py`](./sorting.py) | 3-Way QuickSort & Stable MergeSort | $O(N \log N)$ | Rapid multi-attribute ranking for high-volume threat scans |
| [`engine.py`](./engine.py) | Unified DSA Facade | Pipeline | Integrates all algorithms directly with FastAPI `scan_service` |

---

## Unit & Integration Testing

Run the DSA test suite:
```powershell
$env:PYTHONPATH="02-dsa-engine"; .\.venv\Scripts\python.exe -m pytest 02-dsa-engine/tests -v
```

Run combined backend & DSA integration tests:
```powershell
.\.venv\Scripts\python.exe -m pytest 02-dsa-engine/tests 01-backend/tests -v
```

---

## Backend Integration & API Usage

The DSA Engine is directly integrated into `01-backend`:
- **Domain Reputation (`ThreatDomainHashMap`)**: Injected into `scan_service.py` to immediately classify trusted or malicious domains in $O(1)$ time.
- **Lure & Token Matching (`SuspiciousPatternTrie`)**: Scans URLs for credential harvesting, financial impersonation, and urgency lures in $O(L)$ time.
- **Redirect Loop & Topology (`ThreatGraph`)**: Analyzes `URL -> Domain -> IP` chains and detects evasion loops.
- **Incident Triage (`IncidentPriorityQueue`)**: Powers `GET /api/incidents/triage` and `GET /api/incidents?sort_by=priority` via an indexed Max-Heap.
- **Full-Text Incident Search (`IncidentInvertedIndex`)**: Powers multi-attribute token matching in `GET /api/incidents?search=...`.
- **Multi-pass Incident Ranking (`mergesort_incidents`)**: Guarantees stable $O(N \log N)$ sorting by severity.

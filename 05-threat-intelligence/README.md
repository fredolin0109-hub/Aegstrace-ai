# AEGISTRACE — Phase 5: Threat Intelligence

## Overview

The **Threat Intelligence Engine** (`05-threat-intelligence/`) provides a high-performance, modular, multi-source threat intelligence aggregation and reputation scoring layer for the AEGISTRACE cybersecurity platform.

It combines commercial and open threat feeds (VirusTotal, AbuseIPDB, AlienVault OTX, URLScan) with a zero-credential local algorithmic fallback (`02-dsa-engine`), protected by an in-memory TTL cache with Least Recently Used (LRU) eviction to prevent rate-limit exhaustion and eliminate upstream latency bottlenecks.

---

## Architecture & Components

```
05-threat-intelligence/
├── __init__.py                 # Unified package interface and exports
├── README.md                   # Technical documentation and usage guide
├── aggregator.py               # Multi-source ThreatIntelligenceAggregator
├── domain_info.py              # DNS and lexical domain metadata resolver
├── reputation.py               # Composite reputation scoring and confidence calibration
├── cache/
│   ├── __init__.py
│   ├── memory_cache.py         # Thread-safe TTL cache with O(1) LRU eviction
│   └── cache_manager.py        # Target normalization and namespaced caching
├── providers/
│   ├── __init__.py
│   ├── base.py                 # Abstract BaseThreatProvider and ProviderResult dataclass
│   ├── virustotal.py           # VirusTotal v3 API connector
│   ├── abuseipdb.py            # AbuseIPDB v2 API connector
│   ├── alienvault.py           # AlienVault OTX indicator connector
│   ├── urlscan.py              # URLScan.io search connector
│   └── local_fallback.py       # Zero-credential DSA engine & hashmap fallback provider
└── tests/
    ├── test_cache.py           # TTL expiration, hit/miss, and LRU eviction tests
    ├── test_providers.py       # Mocked responses, error resilience, fallback tests
    ├── test_domain_info.py     # Shannon entropy and DNS resolution heuristics
    ├── test_reputation.py      # Weighted composite scoring and override rules
    └── test_aggregator.py      # Aggregation lifecycle, source tracking, caching tests
```

---

## Core Modules

### 1. In-Memory TTL Cache with LRU Eviction (`cache/`)
- **`MemoryCache`**: Thread-safe cache utilizing `threading.RLock` and standard library `collections.OrderedDict`.
  - Supports configurable `max_size` (default 5000) and `default_ttl` (default 3600s / 1 hour).
  - Cache hits refresh entry recency (`move_to_end`).
  - Insertion beyond capacity evicts least-recently-used entries in $O(1)$ time.
  - Active and passive expiration pruning (`cleanup_expired`).
- **`ThreatCacheManager`**: Handles target normalization (canonical URLs, hostnames, and IP addresses) and namespaced key generation (`threat_intel:domain:...`, `threat_intel:ip:...`, `threat_intel:url:...`).

### 2. Standardized Threat Providers (`providers/`)
All providers inherit from `BaseThreatProvider` and return standardized `ProviderResult` instances:
- **`BaseThreatProvider`**: Standardized interface `lookup(target: str, target_type: str) -> ProviderResult`.
- **`VirusTotalProvider`**: VirusTotal v3 API connector reading `VIRUSTOTAL_API_KEY`. Evaluates multi-engine antivirus consensus, malicious counts, tags, and categories. Handles HTTP 429 rate limits gracefully.
- **`AbuseIPDBProvider`**: AbuseIPDB v2 API connector reading `ABUSEIPDB_API_KEY`. Evaluates abuse confidence percentage, report counts, ISP, and country metadata.
- **`AlienVaultOTXProvider`**: AlienVault OTX indicator connector querying active pulses and malware campaign tags.
- **`URLScanProvider`**: URLScan.io search API connector inspecting historical web scans and DOM verdicts.
- **`LocalFallbackProvider`**: Zero-credential, offline-capable fallback provider powered by `02-dsa-engine`'s polynomial `ThreatDomainHashMap`, prefix trie signatures, and local heuristic indicators. **Always available.**

### 3. DNS & Domain Metadata Resolver (`domain_info.py`)
- Computes Shannon character entropy ($H = -\sum p_i \log_2 p_i$) to detect DGA lures.
- Detects high-abuse Top-Level Domains (`.xyz`, `.top`, `.tk`, `.cam`, etc.).
- Resolves authoritative nameservers (`NS` records) and flags suspicious dynamic/disposable DNS services.
- Resolves IPv4 addresses and reverse PTR records with strict timeout preservation protecting the global process environment.
- Flags direct IP host lures and excessive subdomains.

### 4. Reputation & Composite Scoring (`reputation.py`)
- Weighted score fusion across active providers:
  $$\text{composite\_score} = \frac{\sum w_i \cdot \text{threat\_score}_i \cdot \text{conf}_i}{\sum w_i \cdot \text{conf}_i}$$
- **Authoritative Malicious Escalation & Multi-Feed Consensus**: High-confidence detection by any primary provider or consensus among $\ge 2$ malicious detections guarantees a `HIGH_RISK` verdict ($\ge 0.70$).
- **Enterprise Allowlist Safeguard**: Verified trusted domains (e.g. `google.com`, `microsoft.com`) are protected against third-party false positives.
- **Confidence Calibration**: Boosts confidence when providers achieve consensus and reduces confidence under conflicting signals.

### 5. Multi-Source Aggregator (`aggregator.py`)
- **`ThreatIntelligenceAggregator`**:
  - Automatically identifies target types (`domain`, `ip`, `url`), supporting bracketed IPv6 representations.
  - Queries active providers with **per-provider caching** to prevent upstream rate-limit exhaustion.
  - Tracks which providers were active, available, and cached (`sources_consulted`, `sources_available`, `sources_cached`).
  - Attaches domain heuristics and returns structured `AggregatedThreatReport`.

---

## Integration with AEGISTRACE Platform

### Backend Service Integration (`01-backend/`)
1. **On-Demand API Endpoints**:
   - `GET /api/threat-intel/lookup?target=example.com&target_type=domain&refresh=false`:
     Returns full `ThreatIntelLookupResponse` including composite score, verdict, sources consulted, sources cached, indicators, and raw provider details.
   - `GET /api/threat-intel/stats`: Returns telemetry on cache hit ratio, eviction counts, active entries, and available providers.
   - `POST /api/threat-intel/clear-cache`: Flushes the threat intelligence cache on demand.
2. **Analysis Pipeline Fusion (`POST /api/analyze`)**:
   - `perform_scan()` in `scan_service.py` executes `global_threat_aggregator.lookup()`.
   - Threat intelligence verdicts, scores, and indicators are fused into the scan features, bounded safely to avoid SQL truncation, and persisted in the audit trail.

### Agentic AI Integration (`04-agentic-ai/`)
1. **`threat_lookup` Tool**:
   - Enhanced to query `global_threat_aggregator` alongside the local DSA engine and database indicators.
   - Outputs comprehensive evidence and active provider attribution.
2. **`domain_check` Tool**:
   - Enhanced with `DomainInfoResolver` telemetry, entropy calculation, nameserver checks, and DNS heuristics.

---

## Verification & Test Results

The threat intelligence module includes comprehensive unit and integration tests:
- **`test_cache.py`**: Validates hit/miss tracking, TTL expiration, zero TTL immediate expiry, infinite TTL, opportunistic eviction, and LRU eviction order.
- **`test_providers.py`**: Validates mocked provider responses, error handling, rate limiting (HTTP 429), private/loopback IP handling, AlienVault IPv6 endpoints, and database signature matching in local fallback.
- **`test_domain_info.py`**: Validates Shannon entropy, TLD heuristics, nameserver resolution, suspicious nameservers, and socket timeout preservation.
- **`test_reputation.py`**: Validates score fusion, confidence calibration, multi-feed consensus, and override rules.
- **`test_aggregator.py`**: Validates full multi-source lookup, URL normalization sequence, per-provider caching behavior, and source tracking.
- **`test_threat_intel_integration.py`**: Validates end-to-end FastAPI endpoint behavior, cache flushing, parameter validation, and scan pipeline integration.

```bash
# Run all tests across the complete AEGISTRACE platform
pytest
# 100% test pass rate across all 5 platform engines
```

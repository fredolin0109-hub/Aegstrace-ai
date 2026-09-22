from typing import Optional, List, Tuple, Any, Dict
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class DomainEntry:
    domain: str
    category: str           # SAFE, SUSPICIOUS, MALICIOUS
    reputation_score: float # 0.0 (safest) to 1.0 (most malicious)
    threat_type: str        # BENIGN, PHISHING, TYPOSQUATTING, MALWARE, BRAND_SPOOF
    metadata: Dict[str, Any] = field(default_factory=dict)
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatDomainHashMap:
    """
    Custom Hash Map with separate chaining collision resolution and dynamic resizing.
    Uses polynomial rolling hash: h(s) = (sum(ord(s[i]) * 31^i)) % capacity.
    Provides O(1) average lookup for domain reputation verification.
    """

    INITIAL_CAPACITY = 64
    LOAD_FACTOR_THRESHOLD = 0.75

    def __init__(self, initial_capacity: int = INITIAL_CAPACITY):
        self.capacity = max(16, initial_capacity)
        self.buckets: List[List[Tuple[str, DomainEntry]]] = [[] for _ in range(self.capacity)]
        self.count = 0

    def _hash(self, key: str) -> int:
        """Polynomial rolling hash with prime multiplier 31."""
        h = 0
        p = 31
        p_pow = 1
        m = 10**9 + 9
        for ch in key.lower().strip():
            h = (h + ord(ch) * p_pow) % m
            p_pow = (p_pow * p) % m
        return h % self.capacity

    def put(
        self,
        domain: str,
        category: str,
        reputation_score: float,
        threat_type: str = "BENIGN",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Insert or update a domain reputation entry."""
        domain_clean = domain.lower().strip()
        idx = self._hash(domain_clean)
        bucket = self.buckets[idx]

        entry = DomainEntry(
            domain=domain_clean,
            category=category.upper(),
            reputation_score=max(0.0, min(1.0, reputation_score)),
            threat_type=threat_type.upper(),
            metadata=metadata or {},
        )

        for i, (existing_key, _) in enumerate(bucket):
            if existing_key == domain_clean:
                bucket[i] = (domain_clean, entry)
                return

        bucket.append((domain_clean, entry))
        self.count += 1

        if self.load_factor() > self.LOAD_FACTOR_THRESHOLD:
            self._resize(self.capacity * 2)

    def get(self, domain: str) -> Optional[DomainEntry]:
        """Retrieve domain entry in O(1) expected time."""
        domain_clean = domain.lower().strip()
        idx = self._hash(domain_clean)
        bucket = self.buckets[idx]

        for k, entry in bucket:
            if k == domain_clean:
                return entry
        return None

    def contains(self, domain: str) -> bool:
        """Check if domain exists in hash table."""
        return self.get(domain) is not None

    def delete(self, domain: str) -> bool:
        """Remove domain entry from hash table."""
        domain_clean = domain.lower().strip()
        idx = self._hash(domain_clean)
        bucket = self.buckets[idx]

        for i, (k, _) in enumerate(bucket):
            if k == domain_clean:
                del bucket[i]
                self.count -= 1
                return True
        return False

    def size(self) -> int:
        return self.count

    def load_factor(self) -> float:
        return self.count / self.capacity

    def _resize(self, new_capacity: int) -> None:
        """Resize bucket array and rehash all stored elements."""
        old_buckets = self.buckets
        self.capacity = new_capacity
        self.buckets = [[] for _ in range(self.capacity)]
        self.count = 0

        for bucket in old_buckets:
            for key, entry in bucket:
                self.put(
                    domain=entry.domain,
                    category=entry.category,
                    reputation_score=entry.reputation_score,
                    threat_type=entry.threat_type,
                    metadata=entry.metadata,
                )


def create_default_threat_hashmap() -> ThreatDomainHashMap:
    """Pre-populates hashmap with trusted high-traffic domains and known malicious seeds."""
    hmap = ThreatDomainHashMap()

    # Known Trusted / Benign Domains
    trusted = [
        ("google.com", 0.0, "Search & Cloud Platform"),
        ("github.com", 0.0, "Developer Platform"),
        ("microsoft.com", 0.0, "Enterprise Software"),
        ("apple.com", 0.0, "Consumer Tech"),
        ("amazon.com", 0.0, "E-Commerce"),
        ("wikipedia.org", 0.0, "Educational Reference"),
        ("linkedin.com", 0.0, "Professional Network"),
        ("paypal.com", 0.0, "Financial Institution"),
        ("chase.com", 0.0, "Banking Institution"),
        ("netflix.com", 0.0, "Entertainment Media"),
    ]
    for dom, score, desc in trusted:
        hmap.put(dom, category="SAFE", reputation_score=score, threat_type="BENIGN", metadata={"description": desc})

    # Known Malicious / Typosquatting / Phishing Seeds
    malicious = [
        ("paypa1.com", 0.98, "TYPOSQUATTING", "Impersonating paypal.com using homoglyph '1'"),
        ("micros0ft.com", 0.98, "TYPOSQUATTING", "Impersonating microsoft.com using homoglyph '0'"),
        ("apple-login-security.xyz", 0.95, "PHISHING", "Brand spoofing Apple ID authentication portal"),
        ("secure-update-banking.top", 0.92, "PHISHING", "Credential harvesting portal targeting bank users"),
        ("verify-account-paypal.cam", 0.96, "PHISHING", "Deceptive financial verification page"),
        ("g00gle-accounts.xyz", 0.97, "BRAND_SPOOF", "Google account impersonation for credential theft"),
        ("chase-online-login.work", 0.94, "PHISHING", "Fake Chase banking sign-in portal"),
        ("steamcommunity-trade.top", 0.95, "MALWARE", "Steam trading session hijacker"),
    ]
    for dom, score, threat, desc in malicious:
        hmap.put(dom, category="MALICIOUS", reputation_score=score, threat_type=threat, metadata={"description": desc})

    return hmap

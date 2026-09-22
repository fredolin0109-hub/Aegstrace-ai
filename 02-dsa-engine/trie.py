from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class TrieMatch:
    pattern: str
    category: str
    severity: str
    weight: float
    start_index: int
    end_index: int


class TrieNode:
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end_of_pattern: bool = False
        self.pattern: Optional[str] = None
        self.category: str = "GENERAL"
        self.severity: str = "LOW"
        self.weight: float = 0.05


class SuspiciousPatternTrie:
    """
    Prefix and substring pattern matching Trie for high-throughput URL inspection.
    Scans URLs in O(L * max_pattern_len) time to identify deceptive keywords,
    credential harvesting pathways, and urgent social engineering lures.
    """

    def __init__(self):
        self.root = TrieNode()
        self.pattern_count = 0

    def insert(
        self,
        pattern: str,
        category: str = "GENERAL",
        severity: str = "MEDIUM",
        weight: float = 0.10
    ) -> None:
        """Insert a suspicious pattern keyword into the Trie."""
        clean = pattern.lower().strip()
        if not clean:
            return

        curr = self.root
        for ch in clean:
            if ch not in curr.children:
                curr.children[ch] = TrieNode()
            curr = curr.children[ch]

        curr.is_end_of_pattern = True
        curr.pattern = clean
        curr.category = category.upper()
        curr.severity = severity.upper()
        curr.weight = weight
        self.pattern_count += 1

    def exact_search(self, pattern: str) -> Optional[Dict[str, Any]]:
        """Check if an exact pattern exists in the Trie."""
        clean = pattern.lower().strip()
        curr = self.root
        for ch in clean:
            if ch not in curr.children:
                return None
            curr = curr.children[ch]

        if curr.is_end_of_pattern:
            return {
                "pattern": curr.pattern,
                "category": curr.category,
                "severity": curr.severity,
                "weight": curr.weight,
            }
        return None

    def starts_with(self, prefix: str) -> List[str]:
        """Return all stored patterns starting with a given prefix."""
        clean = prefix.lower().strip()
        curr = self.root
        for ch in clean:
            if ch not in curr.children:
                return []
            curr = curr.children[ch]

        results: List[str] = []
        self._dfs_collect(curr, results)
        return results

    def _dfs_collect(self, node: TrieNode, results: List[str]) -> None:
        if node.is_end_of_pattern and node.pattern:
            results.append(node.pattern)
        for child in node.children.values():
            self._dfs_collect(child, results)

    def scan_text(self, text: str) -> List[TrieMatch]:
        """
        Multi-pattern substring scanner.
        Traverses the text from every starting index through the Trie,
        finding all matching phishing patterns and their locations.
        """
        clean_text = text.lower()
        n = len(clean_text)
        matches: List[TrieMatch] = []
        seen_patterns = set()

        for i in range(n):
            curr = self.root
            j = i
            while j < n and clean_text[j] in curr.children:
                curr = curr.children[clean_text[j]]
                if curr.is_end_of_pattern and curr.pattern:
                    match_key = (curr.pattern, i)
                    if match_key not in seen_patterns:
                        seen_patterns.add(match_key)
                        matches.append(TrieMatch(
                            pattern=curr.pattern,
                            category=curr.category,
                            severity=curr.severity,
                            weight=curr.weight,
                            start_index=i,
                            end_index=j + 1,
                        ))
                j += 1

        return matches


def create_default_pattern_trie() -> SuspiciousPatternTrie:
    """Instantiate and populate Trie with recognized phishing lures and indicators."""
    trie = SuspiciousPatternTrie()

    patterns = [
        # Credential Harvesting
        ("login", "CREDENTIAL_HARVESTING", "MEDIUM", 0.10),
        ("signin", "CREDENTIAL_HARVESTING", "MEDIUM", 0.10),
        ("password", "CREDENTIAL_HARVESTING", "HIGH", 0.20),
        ("credential", "CREDENTIAL_HARVESTING", "HIGH", 0.20),
        ("authenticate", "CREDENTIAL_HARVESTING", "MEDIUM", 0.10),
        ("auth-token", "CREDENTIAL_HARVESTING", "HIGH", 0.15),
        ("verify-account", "CREDENTIAL_HARVESTING", "HIGH", 0.20),
        ("account-update", "CREDENTIAL_HARVESTING", "HIGH", 0.15),

        # Financial & Payment Impersonation
        ("paypal-verify", "FINANCIAL_IMPERSONATION", "CRITICAL", 0.30),
        ("banking-online", "FINANCIAL_IMPERSONATION", "CRITICAL", 0.25),
        ("billing-secure", "FINANCIAL_IMPERSONATION", "HIGH", 0.20),
        ("card-validation", "FINANCIAL_IMPERSONATION", "CRITICAL", 0.30),
        ("wallet-connect", "CRYPTO_TARGET", "HIGH", 0.25),
        ("metamask-restore", "CRYPTO_TARGET", "CRITICAL", 0.35),
        ("seed-phrase", "CRYPTO_TARGET", "CRITICAL", 0.35),

        # Social Engineering & Urgency Lures
        ("security-alert", "URGENT_ACTION", "MEDIUM", 0.15),
        ("account-suspended", "URGENT_ACTION", "HIGH", 0.20),
        ("action-required", "URGENT_ACTION", "MEDIUM", 0.15),
        ("session-expired", "URGENT_ACTION", "HIGH", 0.20),
        ("recover-access", "URGENT_ACTION", "MEDIUM", 0.15),

        # Brand Spoofing Tokens
        ("appleid-verify", "BRAND_SPOOF", "CRITICAL", 0.30),
        ("microsoft-auth", "BRAND_SPOOF", "CRITICAL", 0.30),
        ("google-security", "BRAND_SPOOF", "HIGH", 0.25),
        ("amazon-orders-update", "BRAND_SPOOF", "HIGH", 0.25),
    ]

    for pat, cat, sev, wt in patterns:
        trie.insert(pattern=pat, category=cat, severity=sev, weight=wt)

    return trie

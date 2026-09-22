import re
from typing import List, Dict, Optional, Tuple, Any, Set
from collections import defaultdict


def binary_search_domain(sorted_domains: List[str], target_domain: str) -> Tuple[bool, int]:
    """
    Classic binary search over lexicographically sorted list of known domains.
    Returns: (found: bool, index: int)
    If found is False, index is the insertion point.
    """
    target = target_domain.lower().strip()
    low = 0
    high = len(sorted_domains) - 1

    while low <= high:
        mid = (low + high) // 2
        mid_val = sorted_domains[mid].lower().strip()

        if mid_val == target:
            return True, mid
        elif mid_val < target:
            low = mid + 1
        else:
            high = mid - 1

    return False, low


def binary_search_ip_range(sorted_ranges: List[Tuple[int, int, str]], target_ip_int: int) -> Optional[str]:
    """
    Binary search over non-overlapping sorted IP integer ranges [start_int, end_int, threat_label].
    O(log N) lookup to determine if target IP falls within a known malicious block.
    """
    low = 0
    high = len(sorted_ranges) - 1

    while low <= high:
        mid = (low + high) // 2
        start_ip, end_ip, threat_label = sorted_ranges[mid]

        if start_ip <= target_ip_int <= end_ip:
            return threat_label
        elif target_ip_int < start_ip:
            high = mid - 1
        else:
            low = mid + 1

    return None


class IncidentInvertedIndex:
    """
    Inverted index data structure for high-speed multi-attribute security searching.
    Indexes incident titles, descriptions, target domains, and threat indicators.
    Provides AND/OR set-query retrieval with Term Frequency (TF) ranking.
    """

    def __init__(self):
        # term -> {doc_id: term_frequency}
        self.index: Dict[str, Dict[str, int]] = defaultdict(dict)
        self.doc_store: Dict[str, Dict[str, Any]] = {}

    def _tokenize(self, text: str) -> List[str]:
        """Split into lower-case alphanumeric and compound tokens."""
        if not text:
            return []
        tokens = []
        # Individual words (letters and numbers)
        words = [t.lower() for t in re.findall(r"[a-zA-Z0-9]+", text) if len(t) > 1]
        tokens.extend(words)
        # Compound hyphenated/underscored tokens
        compounds = [t.lower() for t in re.findall(r"[a-zA-Z0-9]+(?:[-_][a-zA-Z0-9]+)+", text)]
        tokens.extend(compounds)
        return tokens

    def add_document(self, doc_id: str, fields: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a document (e.g. incident or scan record) to the inverted index."""
        clean_id = str(doc_id).strip()
        combined_text = " ".join(str(v) for v in fields.values() if v is not None)
        tokens = self._tokenize(combined_text)

        self.doc_store[clean_id] = {
            "id": clean_id,
            "fields": fields,
            "metadata": metadata or {},
        }

        term_counts: Dict[str, int] = defaultdict(int)
        for token in tokens:
            term_counts[token] += 1

        for term, count in term_counts.items():
            self.index[term][clean_id] = count

    def search(self, query: str, mode: str = "AND") -> List[Dict[str, Any]]:
        """
        Execute token search across indexed documents.
        mode: "AND" (all tokens required) or "OR" (any token matched).
        Returns documents ranked by cumulative term frequency score.
        """
        tokens = self._tokenize(query)
        if not tokens:
            return []

        doc_scores: Dict[str, float] = defaultdict(float)

        if mode.upper() == "AND":
            # Must appear in all token posting lists
            matching_doc_sets = []
            for t in tokens:
                if t in self.index:
                    matching_doc_sets.append(set(self.index[t].keys()))
                else:
                    return []  # AND query fails if any term not found

            common_docs = set.intersection(*matching_doc_sets)
            for doc_id in common_docs:
                doc_scores[doc_id] = sum(self.index[t][doc_id] for t in tokens)

        else:  # OR mode
            for t in tokens:
                if t in self.index:
                    for doc_id, count in self.index[t].items():
                        doc_scores[doc_id] += count

        ranked_docs = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for doc_id, score in ranked_docs:
            doc_data = self.doc_store[doc_id].copy()
            doc_data["relevance_score"] = score
            results.append(doc_data)

        return results

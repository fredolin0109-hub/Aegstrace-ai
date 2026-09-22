import os
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
import requests

from providers.base import BaseThreatProvider, ProviderResult


class URLScanProvider(BaseThreatProvider):
    """
    URLScan.io API connector.
    Inspects publicly scanned submissions, DOM verdicts, and malicious classifications.
    Gracefully handles missing keys and rate limits.
    """

    SEARCH_ENDPOINT = "https://urlscan.io/api/v1/search/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        weight: float = 0.20,
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        super().__init__(source_name="urlscan", weight=weight, enabled=enabled, timeout=timeout)
        self.api_key = api_key if api_key is not None else os.getenv("URLSCAN_API_KEY", "")

    def is_available(self) -> bool:
        """URLScan requires an API key to query."""
        return self.enabled and bool(self.api_key and self.api_key.strip())

    def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
        if not self.is_available():
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=False,
                error_message="URLScan provider disabled",
            )

        norm = self.normalize_target(target, target_type)
        if not norm:
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=False,
                error_message="Invalid target provided",
            )

        if target_type == "url":
            parsed_host = urlparse(norm if "://" in norm else f"http://{norm}").hostname or norm
            query = f"domain:{parsed_host}"
        elif target_type == "ip":
            query = f"ip:{norm}"
        else:
            query = f"domain:{norm}"
        params = {"q": query, "size": 5}
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key

        try:
            resp = requests.get(self.SEARCH_ENDPOINT, headers=headers, params=params, timeout=self.timeout)

            if resp.status_code == 429:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": 429},
                    available=False,
                    error_message="URLScan rate limit reached (HTTP 429)",
                )

            if resp.status_code in (401, 403):
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": resp.status_code},
                    available=False,
                    error_message=f"URLScan API key authorization failure (HTTP {resp.status_code})",
                )

            if resp.status_code != 200:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": resp.status_code},
                    available=False,
                    error_message=f"URLScan request returned HTTP {resp.status_code}",
                )

            payload = resp.json()
            results = payload.get("results", [])
            total_results = payload.get("total", len(results))

            malicious_count = 0
            categories: List[str] = []

            for r in results:
                verdicts = r.get("verdicts", {})
                overall = verdicts.get("overall", {})
                if overall.get("malicious"):
                    malicious_count += 1
                    cats = overall.get("categories", [])
                    if isinstance(cats, list):
                        for c in cats:
                            if c not in categories:
                                categories.append(c)

            if malicious_count > 0:
                threat_score = min(1.0, 0.60 + (malicious_count / max(1, len(results))) * 0.40)
                is_malicious = True
                confidence = 0.85
            elif total_results > 0:
                threat_score = 0.0
                is_malicious = False
                confidence = 0.70
            else:
                threat_score = 0.05
                is_malicious = False
                confidence = 0.40

            return ProviderResult(
                source_name=self.source_name,
                is_malicious=is_malicious,
                threat_score=round(threat_score, 4),
                confidence=round(confidence, 4),
                categories=categories,
                raw_data={"total_scans": total_results, "malicious_scans": malicious_count},
                available=True,
            )

        except Exception as exc:
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=False,
                error_message=f"URLScan error: {str(exc)}",
            )

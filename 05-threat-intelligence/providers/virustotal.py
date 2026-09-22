import os
import base64
from typing import Optional, Dict, Any, List
import requests

from providers.base import BaseThreatProvider, ProviderResult


class VirusTotalProvider(BaseThreatProvider):
    """
    VirusTotal v3 API threat intelligence connector.
    Inspects reputation and multi-engine antivirus consensus for domains, IPs, and URLs.
    Handles missing keys, rate limits, and network errors gracefully.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        weight: float = 0.35,
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        super().__init__(source_name="virustotal", weight=weight, enabled=enabled, timeout=timeout)
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")

    def is_available(self) -> bool:
        """VirusTotal requires a non-empty API key to query."""
        return self.enabled and bool(self.api_key and self.api_key.strip())

    def _get_url_identifier(self, url: str) -> str:
        """Computes VirusTotal v3 base64 URL identifier without padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
        """
        Executes VirusTotal v3 lookup for target.
        Returns a standardized ProviderResult without throwing exceptions.
        """
        if not self.is_available():
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=False,
                error_message="VirusTotal API key not configured or provider disabled",
            )

        norm_target = self.normalize_target(target, target_type)
        if not norm_target:
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

        # Build endpoint according to target type
        if target_type == "ip":
            endpoint = f"{self.BASE_URL}/ip_addresses/{norm_target}"
        elif target_type == "url":
            url_id = self._get_url_identifier(norm_target)
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
        else:  # domain
            endpoint = f"{self.BASE_URL}/domains/{norm_target}"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=self.timeout)

            # Handle Rate Limiting
            if response.status_code == 429:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": 429},
                    available=False,
                    error_message="VirusTotal API rate limit exceeded (HTTP 429)",
                )

            # Handle Authentication / Permission errors
            if response.status_code in (401, 403):
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": response.status_code},
                    available=False,
                    error_message=f"VirusTotal authentication failure (HTTP {response.status_code})",
                )

            # Handle Not Found (target not yet scanned by VT)
            if response.status_code == 404:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.05,
                    confidence=0.40,
                    categories=["NOT_SEEN_IN_VT"],
                    raw_data={"status_code": 404, "message": "Target not observed in VirusTotal database"},
                    available=True,
                    error_message=None,
                )

            if response.status_code != 200:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": response.status_code},
                    available=False,
                    error_message=f"VirusTotal query failed with HTTP {response.status_code}",
                )

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected

            categories_dict = attributes.get("categories", {})
            categories: List[str] = list(set(categories_dict.values())) if isinstance(categories_dict, dict) else []
            tags = attributes.get("tags", [])
            if isinstance(tags, list):
                categories.extend(tags)

            # Calculate threat score & confidence
            threat_score = 0.0
            if total > 0:
                if malicious >= 3:
                    threat_score = min(1.0, 0.85 + (malicious / total) * 0.15)
                elif malicious >= 1:
                    threat_score = min(0.80, 0.50 + (malicious / total) * 0.30)
                elif suspicious >= 1:
                    threat_score = min(0.45, 0.30 + (suspicious / total) * 0.20)
                else:
                    threat_score = 0.0

                is_malicious = malicious >= 1 or suspicious >= 3
                confidence = min(0.99, max(0.60, (malicious + harmless) / total))
            else:
                is_malicious = False
                confidence = 0.50

            return ProviderResult(
                source_name=self.source_name,
                is_malicious=is_malicious,
                threat_score=round(threat_score, 4),
                confidence=round(confidence, 4),
                categories=categories[:10],
                raw_data={
                    "last_analysis_stats": stats,
                    "reputation": attributes.get("reputation", 0),
                    "total_engines": total,
                },
                available=True,
                error_message=None,
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
                error_message=f"VirusTotal connection error: {str(exc)}",
            )

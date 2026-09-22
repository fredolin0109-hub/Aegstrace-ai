import os
import ipaddress
from typing import Optional, Dict, Any, List
import requests

from providers.base import BaseThreatProvider, ProviderResult


class AlienVaultOTXProvider(BaseThreatProvider):
    """
    AlienVault OTX (Open Threat Exchange) feed connector.
    Inspects community threat pulses, malware families, and indicator associations.
    Gracefully handles missing keys and rate limits.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(
        self,
        api_key: Optional[str] = None,
        weight: float = 0.20,
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        super().__init__(source_name="alienvault_otx", weight=weight, enabled=enabled, timeout=timeout)
        self.api_key = api_key if api_key is not None else os.getenv("OTX_API_KEY", "")

    def is_available(self) -> bool:
        """AlienVault OTX requires an active API key to query."""
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
                error_message="AlienVault OTX provider disabled",
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

        # Build indicator endpoint
        if target_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(norm)
                ip_type = "IPv6" if ip_obj.version == 6 else "IPv4"
            except ValueError:
                ip_type = "IPv4"
            endpoint = f"{self.BASE_URL}/{ip_type}/{norm}/general"
        elif target_type == "url":
            endpoint = f"{self.BASE_URL}/url/{norm}/general"
        else:
            endpoint = f"{self.BASE_URL}/domain/{norm}/general"

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            resp = requests.get(endpoint, headers=headers, timeout=self.timeout)

            if resp.status_code == 429:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": 429},
                    available=False,
                    error_message="AlienVault OTX rate limit exceeded",
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
                    error_message=f"AlienVault OTX authorization error (HTTP {resp.status_code})",
                )

            if resp.status_code == 404:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.40,
                    categories=["NO_PULSES_FOUND"],
                    raw_data={"pulse_count": 0},
                    available=True,
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
                    error_message=f"AlienVault OTX request returned HTTP {resp.status_code}",
                )

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses", [])

            categories: List[str] = []
            for pulse in pulses[:5]:
                for tag in pulse.get("tags", []):
                    if tag not in categories:
                        categories.append(tag)

            if pulse_count >= 5:
                threat_score = min(1.0, 0.70 + (pulse_count / 50.0) * 0.30)
                is_malicious = True
                confidence = 0.90
            elif pulse_count >= 1:
                threat_score = 0.40 + (pulse_count / 10.0) * 0.25
                is_malicious = True
                confidence = 0.75
            else:
                threat_score = 0.0
                is_malicious = False
                confidence = 0.60

            return ProviderResult(
                source_name=self.source_name,
                is_malicious=is_malicious,
                threat_score=round(threat_score, 4),
                confidence=round(confidence, 4),
                categories=categories[:10],
                raw_data={"pulse_count": pulse_count},
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
                error_message=f"AlienVault OTX error: {str(exc)}",
            )

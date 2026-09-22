import os
import socket
import ipaddress
from typing import Optional, Dict, Any, List
import requests

from providers.base import BaseThreatProvider, ProviderResult


class AbuseIPDBProvider(BaseThreatProvider):
    """
    AbuseIPDB v2 API threat intelligence connector.
    Evaluates IP address abuse confidence scores, historical report frequency, and ISP metadata.
    Handles missing keys, rate limits, and non-IP targets gracefully.
    """

    CHECK_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: Optional[str] = None,
        weight: float = 0.30,
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        super().__init__(source_name="abuseipdb", weight=weight, enabled=enabled, timeout=timeout)
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")

    def is_available(self) -> bool:
        """AbuseIPDB requires a configured API key."""
        return self.enabled and bool(self.api_key and self.api_key.strip())

    def _resolve_ip(self, target: str, target_type: str) -> Optional[str]:
        """Resolves target to an IP string if it is a domain or URL."""
        norm = self.normalize_target(target, target_type)
        if target_type == "ip":
            try:
                return str(ipaddress.ip_address(norm))
            except ValueError:
                return None

        # Check if already a valid IP string
        try:
            return str(ipaddress.ip_address(norm))
        except ValueError:
            pass

        # Try to resolve hostname to IP
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            addr_info = socket.getaddrinfo(norm, None)
            if addr_info:
                return addr_info[0][4][0]
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(orig_timeout)
        return None

    def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
        """Queries AbuseIPDB v2 check API for target IP."""
        if not self.is_available():
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=False,
                error_message="AbuseIPDB API key not configured or provider disabled",
            )

        ip_addr = self._resolve_ip(target, target_type)
        if not ip_addr:
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=True,
                error_message=f"Could not resolve {target_type} '{target}' to a valid IP address",
            )

        # Handle private / loopback / reserved IPs without wasting upstream quota
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.99,
                    categories=["PRIVATE_IP", "NON_ROUTABLE"],
                    raw_data={"ipAddress": ip_addr, "is_private": True},
                    available=True,
                    error_message=None,
                )
        except ValueError:
            pass

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_addr,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            response = requests.get(
                self.CHECK_ENDPOINT,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )

            if response.status_code == 429:
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": 429},
                    available=False,
                    error_message="AbuseIPDB rate limit exceeded (HTTP 429)",
                )

            if response.status_code in (401, 403):
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.0,
                    categories=[],
                    raw_data={"status_code": response.status_code},
                    available=False,
                    error_message=f"AbuseIPDB authentication failure (HTTP {response.status_code})",
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
                    error_message=f"AbuseIPDB request returned HTTP {response.status_code}",
                )

            payload = response.json()
            data = payload.get("data", {})

            abuse_confidence_score = float(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            is_whitelisted = bool(data.get("isWhitelisted", False))

            categories: List[str] = []
            if data.get("usageType"):
                categories.append(f"usage:{data['usageType']}")
            if data.get("countryCode"):
                categories.append(f"country:{data['countryCode']}")

            if is_whitelisted:
                threat_score = 0.0
                is_malicious = False
                confidence = 0.95
                categories.append("WHITELISTED")
            else:
                threat_score = min(1.0, max(0.0, abuse_confidence_score / 100.0))
                is_malicious = threat_score >= 0.25 or total_reports >= 5
                confidence = 0.90 if total_reports > 0 else 0.60

            return ProviderResult(
                source_name=self.source_name,
                is_malicious=is_malicious,
                threat_score=round(threat_score, 4),
                confidence=round(confidence, 4),
                categories=categories,
                raw_data={
                    "ipAddress": ip_addr,
                    "abuseConfidenceScore": abuse_confidence_score,
                    "totalReports": total_reports,
                    "isWhitelisted": is_whitelisted,
                    "isp": data.get("isp"),
                    "countryCode": data.get("countryCode"),
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
                error_message=f"AbuseIPDB connection error: {str(exc)}",
            )

import re
import math
import socket
import ipaddress
import subprocess
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "cam", "fit", "rest", "stream", "live", "link", "guru", "cc", "icu",
    "online", "site", "vip", "support", "account", "cyou", "monster"
}

SUSPICIOUS_NS_PATTERNS = {
    "ddns.net", "no-ip", "duckdns.org", "afraid.org", "zapto.org", "hopto.org"
}


@dataclass
class DomainMetadata:
    domain: str
    primary_ip: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    reverse_dns: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    tld: str = ""
    is_suspicious_tld: bool = False
    entropy: float = 0.0
    is_high_entropy: bool = False
    subdomain_count: int = 0
    is_ip: bool = False
    is_resolvable: bool = False
    heuristics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "primary_ip": self.primary_ip,
            "resolved_ips": self.resolved_ips,
            "reverse_dns": self.reverse_dns,
            "nameservers": self.nameservers,
            "tld": self.tld,
            "is_suspicious_tld": self.is_suspicious_tld,
            "entropy": round(self.entropy, 3),
            "is_high_entropy": self.is_high_entropy,
            "subdomain_count": self.subdomain_count,
            "is_ip": self.is_ip,
            "is_resolvable": self.is_resolvable,
            "heuristics": self.heuristics,
        }


class DomainInfoResolver:
    """
    DNS and domain metadata resolver.
    Calculates lexical Shannon entropy, detects high-risk TLDs,
    performs DNS A-record and PTR lookups, and flags algorithmic anomalies.
    """

    def __init__(self, dns_timeout: float = 1.0):
        self.dns_timeout = dns_timeout

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Computes Shannon entropy in bits per symbol."""
        if not text:
            return 0.0
        counts = Counter(text)
        total = len(text)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    @staticmethod
    def extract_domain(target: str) -> str:
        """Extracts bare hostname/domain from URL or host string."""
        cleaned = target.strip().lower()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.hostname or cleaned
        if "/" in cleaned:
            cleaned = cleaned.split("/")[0]
        if ":" in cleaned and not cleaned.count(":") > 1:
            cleaned = cleaned.split(":")[0]
        return cleaned.strip(".")

    def resolve(self, target: str, resolve_dns: bool = True) -> DomainMetadata:
        """Performs full domain inspection and DNS resolution."""
        domain = self.extract_domain(target)
        if not domain:
            return DomainMetadata(domain="")

        # Check if already raw IP
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False

        entropy = round(self.calculate_entropy(domain), 3)
        is_high_entropy = entropy > 3.85

        # TLD & Subdomains
        tld = ""
        is_suspicious_tld = False
        subdomain_count = 0

        if not is_ip and "." in domain:
            parts = domain.split(".")
            tld = parts[-1]
            is_suspicious_tld = tld in SUSPICIOUS_TLDS
            if len(parts) > 2:
                subdomain_count = len(parts) - 2

        # DNS & Nameserver Resolution
        resolved_ips: List[str] = []
        reverse_dns: Optional[str] = None
        nameservers: List[str] = []
        is_resolvable = False

        if not resolve_dns:
            pass
        elif is_ip:
            resolved_ips = [domain]
            is_resolvable = True
            orig_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.dns_timeout)
                host_info = socket.gethostbyaddr(domain)
                reverse_dns = host_info[0]
            except Exception:
                reverse_dns = None
            finally:
                socket.setdefaulttimeout(orig_timeout)
        else:
            orig_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.dns_timeout)
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
                if resolved_ips:
                    is_resolvable = True
                    try:
                        host_info = socket.gethostbyaddr(resolved_ips[0])
                        reverse_dns = host_info[0]
                    except Exception:
                        reverse_dns = None
            except Exception:
                is_resolvable = False
            finally:
                socket.setdefaulttimeout(orig_timeout)

            # Query authoritative nameservers
            nameservers = self.resolve_nameservers(domain)

        primary_ip = resolved_ips[0] if resolved_ips else None

        # Check for suspicious nameserver patterns
        suspicious_ns = any(
            any(pat in ns for pat in SUSPICIOUS_NS_PATTERNS)
            for ns in nameservers
        )

        heuristics = {
            "digit_count": sum(c.isdigit() for c in domain),
            "hyphen_count": domain.count("-"),
            "domain_length": len(domain),
            "has_hex_sequence": bool(len(domain) > 16 and any(c in "0123456789abcdef" for c in domain)),
            "nameservers_count": len(nameservers),
            "suspicious_nameservers": suspicious_ns,
        }

        return DomainMetadata(
            domain=domain,
            primary_ip=primary_ip,
            resolved_ips=resolved_ips,
            reverse_dns=reverse_dns,
            nameservers=nameservers,
            tld=tld,
            is_suspicious_tld=is_suspicious_tld,
            entropy=entropy,
            is_high_entropy=is_high_entropy,
            subdomain_count=subdomain_count,
            is_ip=is_ip,
            is_resolvable=is_resolvable,
            heuristics=heuristics,
        )

    def resolve_nameservers(self, domain: str) -> List[str]:
        """
        Resolves authoritative nameservers for domain using DNS NS query.
        Returns list of nameserver hostnames, or empty list on failure.
        """
        if not domain or "." not in domain:
            return []
        try:
            result = subprocess.run(
                ["nslookup", "-type=ns", domain],
                capture_output=True,
                text=True,
                timeout=min(self.dns_timeout, 2.0),
            )
            if result.returncode == 0 and result.stdout:
                matches = re.findall(
                    r"nameserver\s*=\s*([a-zA-Z0-9\.\-]+)",
                    result.stdout,
                    re.IGNORECASE,
                )
                seen = set()
                cleaned_ns = []
                for ns in matches:
                    ns_clean = ns.strip().lower().rstrip(".")
                    if ns_clean and ns_clean not in seen:
                        seen.add(ns_clean)
                        cleaned_ns.append(ns_clean)
                return cleaned_ns
        except Exception:
            pass
        return []


default_domain_resolver = DomainInfoResolver()

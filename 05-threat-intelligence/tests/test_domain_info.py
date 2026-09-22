from unittest.mock import patch
import socket
import pytest

from domain_info import DomainInfoResolver, DomainMetadata


def test_entropy_calculation():
    resolver = DomainInfoResolver()
    # Monotonic string should have zero entropy
    assert resolver.calculate_entropy("aaaaaa") == 0.0
    assert resolver.calculate_entropy("") == 0.0

    # High entropy randomized string
    random_str = "x8f9a2b1q7w3z5c4"
    ent = resolver.calculate_entropy(random_str)
    assert ent > 3.5


def test_extract_domain():
    resolver = DomainInfoResolver()
    assert resolver.extract_domain("https://Sub.Example.com:8443/path/index.html") == "sub.example.com"
    assert resolver.extract_domain("http://192.168.1.1:8080/login") == "192.168.1.1"
    assert resolver.extract_domain("malicious.top/") == "malicious.top"
    assert resolver.extract_domain("") == ""


def test_suspicious_tld_flag():
    resolver = DomainInfoResolver()
    meta = resolver.resolve("phishing-portal.xyz", resolve_dns=False)
    assert meta.is_suspicious_tld is True
    assert meta.tld == "xyz"

    meta_top = resolver.resolve("fake-bank.top", resolve_dns=False)
    assert meta_top.is_suspicious_tld is True

    meta_com = resolver.resolve("trusted.com", resolve_dns=False)
    assert meta_com.is_suspicious_tld is False
    assert meta_com.tld == "com"


def test_direct_ip_target():
    resolver = DomainInfoResolver()
    meta = resolver.resolve("127.0.0.1")
    assert meta.is_ip is True
    assert meta.is_resolvable is True
    assert meta.primary_ip == "127.0.0.1"
    assert meta.tld == ""


@patch("socket.getaddrinfo")
@patch("socket.gethostbyaddr")
def test_dns_resolution_success(mock_ptr, mock_dns):
    mock_dns.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
    ]
    mock_ptr.return_value = ("ptr.example.com", [], ["93.184.216.34"])

    resolver = DomainInfoResolver()
    meta = resolver.resolve("example.com")
    assert meta.is_resolvable is True
    assert meta.primary_ip == "93.184.216.34"
    assert meta.reverse_dns == "ptr.example.com"
    assert "93.184.216.34" in meta.resolved_ips


@patch("socket.getaddrinfo")
def test_dns_resolution_failure(mock_dns):
    mock_dns.side_effect = socket.gaierror(-2, "Name or service not known")

    resolver = DomainInfoResolver()
    meta = resolver.resolve("non-existent-domain-109283091.invalid")
    assert meta.is_resolvable is False
    assert meta.primary_ip is None
    assert len(meta.resolved_ips) == 0

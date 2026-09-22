from unittest.mock import patch, MagicMock
import pytest
import requests

from providers.base import BaseThreatProvider, ProviderResult
from providers.virustotal import VirusTotalProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.alienvault import AlienVaultOTXProvider
from providers.urlscan import URLScanProvider
from providers.local_fallback import LocalFallbackProvider


def test_base_provider_contract():
    class DummyProvider(BaseThreatProvider):
        def is_available(self) -> bool:
            return True

        def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.1,
                confidence=0.8,
                categories=["test"],
            )

    provider = DummyProvider(source_name="dummy", weight=0.5)
    assert provider.is_available() is True
    res = provider.lookup("test.com")
    assert res.source_name == "dummy"
    assert res.is_malicious is False
    assert res.to_dict()["threat_score"] == 0.1
    assert provider.normalize_target("https://WWW.Foo.Com/path", "domain") == "www.foo.com"
    assert provider.normalize_target(" 1.1.1.1 ", "ip") == "1.1.1.1"


def test_virustotal_missing_api_key():
    vt = VirusTotalProvider(api_key="")
    assert vt.is_available() is False
    res = vt.lookup("suspicious.com")
    assert res.available is False
    assert res.is_malicious is False
    assert "not configured" in res.error_message


@patch("requests.get")
def test_virustotal_mock_malicious_response(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 15,
                },
                "categories": {"Forcepoint": "phishing", "Kaspersky": "malware"},
                "tags": ["phishing", "trojan"],
            }
        }
    }
    mock_get.return_value = mock_resp

    vt = VirusTotalProvider(api_key="dummy_vt_key")
    assert vt.is_available() is True
    res = vt.lookup("malware-domain.com", "domain")

    assert res.available is True
    assert res.is_malicious is True
    assert res.threat_score >= 0.85
    assert res.confidence >= 0.70
    assert "phishing" in res.categories


@patch("requests.get")
def test_virustotal_mock_harmless_response(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 2,
                },
                "categories": {},
                "tags": [],
            }
        }
    }
    mock_get.return_value = mock_resp

    vt = VirusTotalProvider(api_key="dummy_vt_key")
    res = vt.lookup("harmless.org")

    assert res.available is True
    assert res.is_malicious is False
    assert res.threat_score == 0.0
    assert res.confidence >= 0.90


@patch("requests.get")
def test_virustotal_rate_limit_and_errors(mock_get):
    # 429 Rate limit
    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_get.return_value = mock_429

    vt = VirusTotalProvider(api_key="dummy_vt_key")
    res_429 = vt.lookup("target.com")
    assert res_429.available is False
    assert "rate limit" in res_429.error_message.lower()

    # Network Exception
    mock_get.side_effect = requests.RequestException("Connection timed out")
    res_err = vt.lookup("target.com")
    assert res_err.available is False
    assert "connection error" in res_err.error_message.lower()


def test_abuseipdb_missing_key():
    ab = AbuseIPDBProvider(api_key="")
    assert ab.is_available() is False
    res = ab.lookup("1.2.3.4", "ip")
    assert res.available is False
    assert "not configured" in res.error_message


@patch("requests.get")
def test_abuseipdb_mock_abusive_ip(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.12",
            "abuseConfidenceScore": 88,
            "totalReports": 34,
            "isWhitelisted": False,
            "isp": "BadHost Ltd",
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting",
        }
    }
    mock_get.return_value = mock_resp

    ab = AbuseIPDBProvider(api_key="dummy_ab_key")
    assert ab.is_available() is True
    res = ab.lookup("198.51.100.12", "ip")

    assert res.available is True
    assert res.is_malicious is True
    assert res.threat_score == 0.88
    assert res.confidence >= 0.85
    assert "country:RU" in res.categories


@patch("requests.get")
def test_abuseipdb_whitelisted_ip(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isWhitelisted": True,
            "isp": "Google LLC",
            "countryCode": "US",
        }
    }
    mock_get.return_value = mock_resp

    ab = AbuseIPDBProvider(api_key="dummy_ab_key")
    res = ab.lookup("8.8.8.8", "ip")
    assert res.available is True
    assert res.is_malicious is False
    assert res.threat_score == 0.0
    assert "WHITELISTED" in res.categories


@patch("requests.get")
def test_alienvault_otx_mock_pulse(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "pulse_info": {
            "count": 6,
            "pulses": [
                {"name": "Lazarus Phishing Campaign", "tags": ["apt", "phishing", "malware"]}
            ]
        }
    }
    mock_get.return_value = mock_resp

    otx = AlienVaultOTXProvider(api_key="test_key")
    res = otx.lookup("apt-domain.com")
    assert res.available is True
    assert res.is_malicious is True
    assert res.threat_score >= 0.70
    assert "phishing" in res.categories


@patch("requests.get")
def test_urlscan_mock_result(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "total": 3,
        "results": [
            {"verdicts": {"overall": {"malicious": True, "categories": ["phishing"]}}}
        ]
    }
    mock_get.return_value = mock_resp

    us = URLScanProvider(api_key="mock_key")
    res = us.lookup("phish-target.com")
    assert res.available is True
    assert res.is_malicious is True
    assert res.threat_score >= 0.60


def test_local_fallback_provider():
    local = LocalFallbackProvider()
    assert local.is_available() is True

    # 1. Known malicious in 02-dsa-engine seed list
    res_mal = local.lookup("paypa1.com")
    assert res_mal.available is True
    assert res_mal.is_malicious is True
    assert res_mal.threat_score >= 0.90
    assert "TYPOSQUATTING" in res_mal.categories

    # 2. Known trusted in allowlist
    res_safe = local.lookup("google.com")
    assert res_safe.available is True
    assert res_safe.is_malicious is False
    assert res_safe.threat_score == 0.0
    assert "TRUSTED_ALLOWLIST" in res_safe.categories

    # 3. Suspicious TLD heuristics on unknown domain
    res_tld = local.lookup("random-unknown-domain-test.xyz")
    assert res_tld.available is True
    assert any("SUSPICIOUS_TLD" in c for c in res_tld.categories)


def test_abuseipdb_private_and_loopback_ip():
    ab = AbuseIPDBProvider(api_key="mock_key")
    res_loopback = ab.lookup("127.0.0.1", "ip")
    assert res_loopback.available is True
    assert res_loopback.is_malicious is False
    assert res_loopback.threat_score == 0.0
    assert "PRIVATE_IP" in res_loopback.categories

    res_priv = ab.lookup("192.168.1.1", "ip")
    assert res_priv.available is True
    assert "PRIVATE_IP" in res_priv.categories


@patch("requests.get")
def test_alienvault_ipv6_endpoint(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"pulse_info": {"count": 0, "pulses": []}}
    mock_get.return_value = mock_resp

    otx = AlienVaultOTXProvider(api_key="mock_key")
    _ = otx.lookup("2001:db8::1", target_type="ip")
    assert mock_get.called
    endpoint_called = mock_get.call_args[0][0]
    assert "/IPv6/" in endpoint_called


def test_local_fallback_with_db_signatures():
    from unittest.mock import MagicMock
    import providers.local_fallback as lf_module

    mock_rec = MagicMock()
    mock_rec.indicator_type = "HISTORICAL_PHISH_IOC"
    mock_rec.severity = "HIGH"
    mock_rec.value = "ioc-flagged-target.com"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.limit.return_value.all.return_value = [mock_rec]
    mock_session_factory = MagicMock(return_value=mock_db)

    orig_sl = lf_module.SessionLocal
    orig_ti = lf_module.ThreatIndicator
    try:
        lf_module.SessionLocal = mock_session_factory
        lf_module.ThreatIndicator = MagicMock()

        local = LocalFallbackProvider()
        res = local.lookup("ioc-flagged-target.com")
        assert res.is_malicious is True
        assert res.threat_score >= 0.85
        assert any("DB_INDICATOR:HISTORICAL_PHISH_IOC" in c for c in res.categories)
    finally:
        lf_module.SessionLocal = orig_sl
        lf_module.ThreatIndicator = orig_ti


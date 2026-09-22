import pytest
from hashmap import ThreatDomainHashMap, create_default_threat_hashmap


def test_hashmap_basic_put_get():
    h = ThreatDomainHashMap(initial_capacity=16)
    h.put("example.com", category="SAFE", reputation_score=0.05, threat_type="BENIGN")

    assert h.size() == 1
    assert h.contains("example.com") is True
    assert h.contains("other.com") is False

    entry = h.get("example.com")
    assert entry is not None
    assert entry.domain == "example.com"
    assert entry.category == "SAFE"
    assert entry.reputation_score == 0.05


def test_hashmap_update_and_delete():
    h = ThreatDomainHashMap(initial_capacity=16)
    h.put("evil-login.xyz", category="SUSPICIOUS", reputation_score=0.60)
    assert h.size() == 1

    # Update
    h.put("evil-login.xyz", category="MALICIOUS", reputation_score=0.95)
    assert h.size() == 1
    assert h.get("evil-login.xyz").category == "MALICIOUS"
    assert h.get("evil-login.xyz").reputation_score == 0.95

    # Delete
    deleted = h.delete("evil-login.xyz")
    assert deleted is True
    assert h.size() == 0
    assert h.get("evil-login.xyz") is None


def test_hashmap_dynamic_resizing_and_collisions():
    # Force small capacity to trigger resizing
    h = ThreatDomainHashMap(initial_capacity=16)
    for i in range(50):
        h.put(f"subdomain-{i}.testing-phish.com", category="MALICIOUS", reputation_score=0.8)

    assert h.size() == 50
    assert h.capacity > 16  # verified resize occurred
    assert h.load_factor() <= h.LOAD_FACTOR_THRESHOLD

    # Verify all 50 keys can be retrieved accurately without data loss
    for i in range(50):
        assert h.contains(f"subdomain-{i}.testing-phish.com") is True


def test_default_threat_hashmap():
    h = create_default_threat_hashmap()
    assert h.contains("google.com") is True
    assert h.get("google.com").category == "SAFE"

    assert h.contains("paypa1.com") is True
    assert h.get("paypa1.com").category == "MALICIOUS"
    assert h.get("paypa1.com").threat_type == "TYPOSQUATTING"

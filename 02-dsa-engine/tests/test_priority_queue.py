import pytest
from priority_queue import IncidentPriorityQueue


def test_priority_queue_push_pop_ordering():
    pq = IncidentPriorityQueue()

    pq.push("INC-001", "Low priority adware", severity="LOW", risk_score=0.20)
    pq.push("INC-002", "Critical ransomware domain", severity="CRITICAL", risk_score=0.98)
    pq.push("INC-003", "Medium risk phish", severity="MEDIUM", risk_score=0.55)
    pq.push("INC-004", "High risk brand spoof", severity="HIGH", risk_score=0.85)

    assert pq.size() == 4

    # Pop order must be: CRITICAL (INC-002) -> HIGH (INC-004) -> MEDIUM (INC-003) -> LOW (INC-001)
    top1 = pq.pop()
    assert top1.incident_id == "INC-002"
    assert top1.severity == "CRITICAL"

    top2 = pq.pop()
    assert top2.incident_id == "INC-004"
    assert top2.severity == "HIGH"

    top3 = pq.pop()
    assert top3.incident_id == "INC-003"

    top4 = pq.pop()
    assert top4.incident_id == "INC-001"

    assert pq.is_empty() is True


def test_priority_queue_dynamic_update():
    pq = IncidentPriorityQueue()
    pq.push("INC-100", "Initially low incident", severity="LOW", risk_score=0.10)
    pq.push("INC-200", "High incident", severity="HIGH", risk_score=0.80)

    assert pq.peek().incident_id == "INC-200"

    # Escalate INC-100 to CRITICAL
    updated = pq.update_priority("INC-100", severity="CRITICAL", risk_score=0.99)
    assert updated is True

    # Now INC-100 must be at the root
    assert pq.peek().incident_id == "INC-100"
    assert pq.pop().incident_id == "INC-100"


def test_priority_queue_to_sorted_list_and_push_duplicate():
    pq = IncidentPriorityQueue()
    pq.push("INC-A", "Adware", severity="LOW", risk_score=0.1)
    pq.push("INC-B", "Data Exfil", severity="HIGH", risk_score=0.7)

    # Re-push INC-A with CRITICAL escalation
    pq.push("INC-A", "Escalated Adware to Ransomware", severity="CRITICAL", risk_score=0.95)
    assert pq.size() == 2

    # to_sorted_list without mutating heap
    sorted_items = pq.to_sorted_list()
    assert len(sorted_items) == 2
    assert sorted_items[0].incident_id == "INC-A"
    assert sorted_items[0].title == "Escalated Adware to Ransomware"
    assert sorted_items[1].incident_id == "INC-B"
    # Heap must remain intact
    assert pq.size() == 2
    assert pq.pop().incident_id == "INC-A"

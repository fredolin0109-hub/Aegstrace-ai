import pytest
from sorting import quicksort_threat_scores, mergesort_incidents


def test_quicksort_threat_scores():
    scores = [0.05, 0.95, 0.40, 0.05, 0.85, 0.40, 0.95, 0.10, 0.0]
    sorted_asc = quicksort_threat_scores(scores)
    assert sorted_asc == [0.0, 0.05, 0.05, 0.10, 0.40, 0.40, 0.85, 0.95, 0.95]

    sorted_desc = quicksort_threat_scores(scores, reverse=True)
    assert sorted_desc == [0.95, 0.95, 0.85, 0.40, 0.40, 0.10, 0.05, 0.05, 0.0]


def test_mergesort_stable_incidents():
    incidents = [
        {"id": "INC-1", "severity_rank": 3, "timestamp": 100},
        {"id": "INC-2", "severity_rank": 1, "timestamp": 101},
        {"id": "INC-3", "severity_rank": 3, "timestamp": 102},
        {"id": "INC-4", "severity_rank": 2, "timestamp": 103},
    ]

    # Stable sort by severity_rank descending
    sorted_inc = mergesort_incidents(incidents, key=lambda x: x["severity_rank"], reverse=True)

    assert sorted_inc[0]["id"] == "INC-1"  # INC-1 and INC-3 both have rank 3, INC-1 was first
    assert sorted_inc[1]["id"] == "INC-3"
    assert sorted_inc[2]["id"] == "INC-4"
    assert sorted_inc[3]["id"] == "INC-2"

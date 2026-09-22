from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone


SEVERITY_WEIGHTS = {
    "CRITICAL": 1000.0,
    "HIGH": 500.0,
    "MEDIUM": 200.0,
    "LOW": 50.0,
}


@dataclass
class IncidentPriorityItem:
    incident_id: str
    title: str
    severity: str
    risk_score: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    priority_key: float = 0.0

    def compute_priority(self) -> float:
        base = SEVERITY_WEIGHTS.get(self.severity.upper(), 100.0)
        risk_part = self.risk_score * 100.0
        # Composite priority score
        self.priority_key = base + risk_part
        return self.priority_key


class IncidentPriorityQueue:
    """
    Max-Heap based Priority Queue for automated SOC incident triage.
    Higher priority incidents (Critical severity, high threat score) always bubble to the top.
    Maintains O(1) position lookup map for O(log N) updates.
    """

    def __init__(self):
        self.heap: List[IncidentPriorityItem] = []
        self.pos_map: Dict[str, int] = {}  # incident_id -> index in heap

    def push(
        self,
        incident_id: str,
        title: str,
        severity: str,
        risk_score: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Insert incident into the priority queue."""
        clean_id = str(incident_id).strip()
        item = IncidentPriorityItem(
            incident_id=clean_id,
            title=title,
            severity=severity.upper(),
            risk_score=max(0.0, min(1.0, risk_score)),
            metadata=metadata or {},
        )
        item.compute_priority()

        if clean_id in self.pos_map:
            # Update existing
            self.update_priority(clean_id, severity=severity, risk_score=risk_score, title=title, metadata=metadata)
            return

        idx = len(self.heap)
        self.heap.append(item)
        self.pos_map[clean_id] = idx
        self._sift_up(idx)

    def pop(self) -> Optional[IncidentPriorityItem]:
        """Extract highest-priority incident in O(log N)."""
        if not self.heap:
            return None

        top = self.heap[0]
        last = self.heap.pop()
        del self.pos_map[top.incident_id]

        if self.heap:
            self.heap[0] = last
            self.pos_map[last.incident_id] = 0
            self._sift_down(0)

        return top

    def peek(self) -> Optional[IncidentPriorityItem]:
        """Inspect top-priority incident in O(1) without removal."""
        return self.heap[0] if self.heap else None

    def update_priority(
        self,
        incident_id: str,
        severity: Optional[str] = None,
        risk_score: Optional[float] = None,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update incident attributes and restore heap invariant in O(log N)."""
        clean_id = str(incident_id).strip()
        if clean_id not in self.pos_map:
            return False

        idx = self.pos_map[clean_id]
        item = self.heap[idx]

        if title is not None:
            item.title = title
        if metadata is not None:
            item.metadata.update(metadata)
        if severity:
            item.severity = severity.upper()
        if risk_score is not None:
            item.risk_score = max(0.0, min(1.0, risk_score))

        old_p = item.priority_key
        new_p = item.compute_priority()

        if new_p > old_p:
            self._sift_up(idx)
        else:
            self._sift_down(idx)
        return True

    def size(self) -> int:
        return len(self.heap)

    def is_empty(self) -> bool:
        return len(self.heap) == 0

    def to_sorted_list(self) -> List[IncidentPriorityItem]:
        """Returns all items ordered by priority descending without mutating the heap."""
        # Clone heap and pop all while preserving metadata and timestamps
        clone = IncidentPriorityQueue()
        for item in self.heap:
            cloned_item = IncidentPriorityItem(
                incident_id=item.incident_id,
                title=item.title,
                severity=item.severity,
                risk_score=item.risk_score,
                created_at=item.created_at,
                metadata=item.metadata.copy() if item.metadata else {},
                priority_key=item.priority_key,
            )
            idx = len(clone.heap)
            clone.heap.append(cloned_item)
            clone.pos_map[cloned_item.incident_id] = idx

        sorted_items = []
        while not clone.is_empty():
            sorted_items.append(clone.pop())
        return sorted_items

    def _sift_up(self, idx: int) -> None:
        while idx > 0:
            parent = (idx - 1) // 2
            if self.heap[idx].priority_key > self.heap[parent].priority_key:
                self._swap(idx, parent)
                idx = parent
            else:
                break

    def _sift_down(self, idx: int) -> None:
        n = len(self.heap)
        while True:
            left = 2 * idx + 1
            right = 2 * idx + 2
            largest = idx

            if left < n and self.heap[left].priority_key > self.heap[largest].priority_key:
                largest = left
            if right < n and self.heap[right].priority_key > self.heap[largest].priority_key:
                largest = right

            if largest != idx:
                self._swap(idx, largest)
                idx = largest
            else:
                break

    def _swap(self, i: int, j: int) -> None:
        self.heap[i], self.heap[j] = self.heap[j], self.heap[i]
        self.pos_map[self.heap[i].incident_id] = i
        self.pos_map[self.heap[j].incident_id] = j

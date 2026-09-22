from typing import List, Callable, Any, TypeVar, Optional

T = TypeVar("T")


def quicksort_threat_scores(
    arr: List[T],
    key: Optional[Callable[[T], float]] = None,
    reverse: bool = False
) -> List[T]:
    """
    3-Way Dutch National Flag QuickSort algorithm.
    Optimized for datasets with large numbers of repeated risk scores or severity values.
    Runs in O(N log N) expected time and O(N) when keys are uniform.
    """
    if len(arr) <= 1:
        return arr[:]

    key_fn = key or (lambda x: x)
    items = arr[:]

    def _sort(lst: List[T]) -> List[T]:
        if len(lst) <= 1:
            return lst

        pivot = lst[len(lst) // 2]
        pivot_val = key_fn(pivot)

        less: List[T] = []
        equal: List[T] = []
        greater: List[T] = []

        for item in lst:
            val = key_fn(item)
            if val < pivot_val:
                less.append(item)
            elif val > pivot_val:
                greater.append(item)
            else:
                equal.append(item)

        if not reverse:
            return _sort(less) + equal + _sort(greater)
        else:
            return _sort(greater) + equal + _sort(less)

    return _sort(items)


def mergesort_incidents(
    arr: List[T],
    key: Optional[Callable[[T], Any]] = None,
    reverse: bool = False
) -> List[T]:
    """
    Stable MergeSort algorithm with O(N log N) worst-case guarantee.
    Preserves input order of equal elements, critical for multi-pass SOC triage
    (e.g., sorting by timestamp then by severity).
    """
    if len(arr) <= 1:
        return arr[:]

    key_fn = key or (lambda x: x)

    def _merge(left: List[T], right: List[T]) -> List[T]:
        result: List[T] = []
        i = j = 0

        while i < len(left) and j < len(right):
            val_l = key_fn(left[i])
            val_r = key_fn(right[j])

            condition = (val_l <= val_r) if not reverse else (val_l >= val_r)
            if condition:
                result.append(left[i])
                i += 1
            else:
                result.append(right[j])
                j += 1

        result.extend(left[i:])
        result.extend(right[j:])
        return result

    mid = len(arr) // 2
    left_sorted = mergesort_incidents(arr[:mid], key=key_fn, reverse=reverse)
    right_sorted = mergesort_incidents(arr[mid:], key=key_fn, reverse=reverse)

    return _merge(left_sorted, right_sorted)

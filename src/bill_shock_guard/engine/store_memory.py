"""In-memory StateStore implementation with optimistic concurrency checking."""

import copy

from bill_shock_guard.models import FindingState, FindingStatus


class OptimisticLockError(Exception):
    """Raised when a conditional write fails due to a version mismatch."""


class MemoryStateStore:
    """In-memory StateStore implementation for tests and CLI usage."""

    def __init__(self) -> None:
        self._states: dict[str, FindingState] = {}

    def get(self, key: str) -> FindingState | None:
        """Retrieve state for a finding key."""
        state = self._states.get(key)
        if state is None:
            return None
        return copy.deepcopy(state)

    def put(self, state: FindingState) -> None:
        """Save state using conditional write semantics on version attribute.

        - If inserting a new item, state.version must be 1 and item must not exist.
        - If updating an existing item, state.version must equal existing.version + 1.
        """
        existing = self._states.get(state.key)
        if existing is None:
            if state.version != 1:
                raise OptimisticLockError(
                    f"Conditional write failed for key '{state.key}': "
                    f"item does not exist but version={state.version}"
                )
        else:
            if state.version != existing.version + 1:
                raise OptimisticLockError(
                    f"Conditional write failed for key '{state.key}': "
                    f"expected version {existing.version + 1}, got {state.version}"
                )
        self._states[state.key] = copy.deepcopy(state)

    def list_open(self) -> list[FindingState]:
        """List all non-terminal findings currently being tracked."""
        open_items: list[FindingState] = []
        for s in self._states.values():
            if s.status in {
                FindingStatus.RESOLVED,
                FindingStatus.ACTED,
                FindingStatus.WOULD_ACT,
            }:
                continue
            if s.status == FindingStatus.FAILED and s.attempts >= 3:
                continue
            open_items.append(copy.deepcopy(s))
        return open_items

    def list_all(self) -> list[FindingState]:
        """List all findings in the store regardless of status."""
        return [copy.deepcopy(s) for s in self._states.values()]

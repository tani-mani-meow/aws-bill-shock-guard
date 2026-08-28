"""Protocols and interfaces for Detectors, Actions, Notifiers, and State Stores."""

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from bill_shock_guard.clock import Clock
from bill_shock_guard.config import Config
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    FindingState,
    RecheckResult,
    ResourceType,
)


@dataclass(frozen=True)
class ScanContext:
    """Execution context injected into detectors, actions, and runners."""

    config: Config
    clock: Clock
    account_id: str
    run_id: str
    logger: JsonLogger
    client_factory: Callable[[str, str], Any]
    on_scan_error: Callable[[str], None] | None = None

    def client(self, service_name: str, region_name: str) -> Any:
        """Obtain a boto3 client for the given service and region."""
        return self.client_factory(service_name, region_name)

    def report_scan_error(self, message: str) -> None:
        """Report incomplete detector coverage while preserving any findings collected."""
        if self.on_scan_error is not None:
            self.on_scan_error(message)


class Detector(Protocol):
    """Protocol for resource scanning and idle detection."""

    resource_type: ResourceType

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan a region and return all detected findings (including protected ones)."""
        ...

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify the live resource state immediately before taking an action."""
        ...


class Action(Protocol):
    """Protocol for executing a remedial action on an idle resource."""

    kind: ActionKind

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Execute the action. Only called when all safety invariants pass."""
        ...


class Notifier(Protocol):
    """Protocol for sending alert digests."""

    name: str

    def send(self, subject: str, body: str) -> bool:
        """Send notification. Returns True if and only if delivery was confirmed."""
        ...


class StateStore(Protocol):
    """Protocol for persisting finding lifecycle states across scheduled runs."""

    def get(self, key: str) -> FindingState | None:
        """Retrieve state for a finding key."""
        ...

    def put(self, state: FindingState) -> None:
        """Save state. Implementations should use conditional writes for concurrency."""
        ...

    def list_open(self) -> list[FindingState]:
        """List all non-terminal findings currently being tracked."""
        ...

"""Engine package for Bill Shock Guard: state machine, stores, and execution runner."""

from bill_shock_guard.engine.runner import EngineRunner, RunSummary, run_engine
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore, OptimisticLockError

__all__ = [
    "decide",
    "MemoryStateStore",
    "DynamoDbStateStore",
    "OptimisticLockError",
    "EngineRunner",
    "RunSummary",
    "run_engine",
]

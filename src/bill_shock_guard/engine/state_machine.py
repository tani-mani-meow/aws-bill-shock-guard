"""Pure state machine transitions for Bill Shock Guard findings."""

from datetime import datetime, timedelta

from bill_shock_guard.config import Config
from bill_shock_guard.models import Decision, Effect, Finding, FindingState, FindingStatus


def decide(
    finding: Finding | None,
    state: FindingState | None,
    now: datetime,
    config: Config,
    actions_taken: int = 0,
) -> Decision:
    """Evaluate pure state transition for a single finding and its prior state.

    Safety Invariants enforced here:
      - I1: Never perform a mutating action when config.dry_run is True.
      - I2: Never act unless a warning was delivered and recorded at least grace_hours earlier.
      - I5: Only perform actions listed in config.enabled_actions.
      - I7: Circuit breaker: at most config.max_actions_per_run mutating actions per run.
      - I8: Idempotent: running on unchanged state causes no duplicate warnings or actions.
      - I10: Adding protect tag cancels pending action.

    Args:
        finding: The finding detected in the current run, or None if no longer detected.
        state: The previously stored FindingState, or None if newly detected.
        now: Current timezone-aware UTC datetime.
        config: Configuration instance.
        actions_taken: Number of actions already taken in this run (for circuit breaker).

    Returns:
        Decision indicating the next FindingStatus, Effect to perform, and reason.
    """
    if state is not None and state.status == FindingStatus.ACTION_PENDING:
        return Decision(
            next_status=FindingStatus.ACTION_PENDING,
            effect=Effect.NONE,
            reason="Prior action outcome needs reconciliation",
        )

    # Case 1: Neither finding nor state exists
    if finding is None and state is None:
        return Decision(
            next_status=FindingStatus.RESOLVED,
            effect=Effect.NONE,
            reason="No finding and no prior state",
        )

    # Case 2: Resource is no longer detected (resolved or gone)
    if finding is None:
        assert state is not None
        if state.status == FindingStatus.RESOLVED:
            return Decision(
                next_status=FindingStatus.RESOLVED,
                effect=Effect.NONE,
                reason="Resource remains resolved",
            )
        if state.status == FindingStatus.ACTED:
            return Decision(
                next_status=FindingStatus.RESOLVED,
                effect=Effect.NONE,
                reason="Acted resource no longer detected",
            )
        return Decision(
            next_status=FindingStatus.RESOLVED,
            effect=Effect.NONE,
            reason="Resource no longer detected as idle; resolved",
        )

    # Case 3: Resource was already acted on (Invariant I8: no duplicate action)
    if state is not None and state.status == FindingStatus.ACTED:
        return Decision(
            next_status=FindingStatus.ACTED,
            effect=Effect.NONE,
            reason="Resource was already acted on",
        )

    # Case 4: Finding is protected (Invariant I3 & I10)
    if finding.protected:
        reason = finding.protection_reason or "Protected resource"
        return Decision(
            next_status=FindingStatus.EXEMPT,
            effect=Effect.NONE,
            reason=reason,
        )

    # Case 5: Finding is unprotected and new (no prior state)
    if state is None:
        return Decision(
            next_status=FindingStatus.DETECTED,
            effect=Effect.SEND_WARNING,
            reason="New idle resource detected; warning queued",
        )

    # Case 6: Resource previously resolved or exempt has reappeared as unprotected idle
    if state.status in {FindingStatus.RESOLVED, FindingStatus.EXEMPT}:
        return Decision(
            next_status=FindingStatus.DETECTED,
            effect=Effect.SEND_WARNING,
            reason="Resource detected as unprotected idle; warning queued",
        )

    # Case 7: Warning pending delivery (prior delivery failed or unconfirmed)
    if state.status == FindingStatus.DETECTED:
        return Decision(
            next_status=FindingStatus.DETECTED,
            effect=Effect.SEND_WARNING,
            reason="Warning delivery pending or retrying",
        )

    # Case 8: Resource is in WARNED state
    if state.status == FindingStatus.WARNED:
        # Invariant I2: Warning must be recorded as delivered with valid warned_at
        if state.warned_at is None:
            return Decision(
                next_status=FindingStatus.DETECTED,
                effect=Effect.SEND_WARNING,
                reason="Warning not recorded as delivered; reverting to DETECTED",
            )

        deadline = state.action_deadline or (state.warned_at + timedelta(hours=config.grace_hours))
        if now < deadline:
            return Decision(
                next_status=FindingStatus.WARNED,
                effect=Effect.NONE,
                reason=f"Grace period active until {deadline.isoformat()}",
            )

        # Grace period has elapsed!
        # Invariant I1: Dry run never mutates
        if config.dry_run:
            return Decision(
                next_status=FindingStatus.WOULD_ACT,
                effect=Effect.NONE,
                reason="Dry run enabled: action would be attempted after grace period",
            )

        # Invariant I5: Proposed action must be non-None and enabled
        if finding.proposed_action is None:
            return Decision(
                next_status=FindingStatus.WARNED,
                effect=Effect.NONE,
                reason="No proposed action specified for resource",
            )

        if finding.proposed_action not in config.enabled_actions:
            return Decision(
                next_status=FindingStatus.WARNED,
                effect=Effect.NONE,
                reason=f"Action {finding.proposed_action.value} is not in enabled_actions",
            )

        # Invariant I7: Circuit breaker
        if actions_taken >= config.max_actions_per_run:
            return Decision(
                next_status=FindingStatus.WARNED,
                effect=Effect.NONE,
                reason=(
                    f"Circuit breaker reached max_actions_per_run "
                    f"({config.max_actions_per_run}); action deferred"
                ),
            )

        # All safety invariants pass
        return Decision(
            next_status=FindingStatus.ACTED,
            effect=Effect.ATTEMPT_ACTION,
            reason=f"Grace period elapsed; attempting {finding.proposed_action.value}",
        )

    # Case 9: Resource is in WOULD_ACT (dry run prior state)
    if state.status == FindingStatus.WOULD_ACT:
        if config.dry_run:
            return Decision(
                next_status=FindingStatus.WOULD_ACT,
                effect=Effect.NONE,
                reason="Dry run active: would act",
            )

        # Dry run turned off: verify action eligibility
        if finding.proposed_action is None or finding.proposed_action not in config.enabled_actions:
            return Decision(
                next_status=FindingStatus.WARNED,
                effect=Effect.NONE,
                reason=f"Action {finding.proposed_action} not enabled",
            )

        if actions_taken >= config.max_actions_per_run:
            return Decision(
                next_status=FindingStatus.WOULD_ACT,
                effect=Effect.NONE,
                reason=(
                    f"Circuit breaker reached max_actions_per_run "
                    f"({config.max_actions_per_run}); action deferred"
                ),
            )

        return Decision(
            next_status=FindingStatus.ACTED,
            effect=Effect.ATTEMPT_ACTION,
            reason=f"Dry run disabled; attempting {finding.proposed_action.value}",
        )

    # Case 10: Resource is in FAILED state (retry up to 3 times)
    if state.status == FindingStatus.FAILED:
        if state.attempts >= 3:
            return Decision(
                next_status=FindingStatus.FAILED,
                effect=Effect.NONE,
                reason=(
                    f"Action failed after {state.attempts} attempts; stopped retrying "
                    f"({state.last_error or 'unknown error'})"
                ),
            )

        if config.dry_run:
            return Decision(
                next_status=FindingStatus.WOULD_ACT,
                effect=Effect.NONE,
                reason="Dry run active: would retry failed action",
            )

        if finding.proposed_action is None or finding.proposed_action not in config.enabled_actions:
            return Decision(
                next_status=FindingStatus.FAILED,
                effect=Effect.NONE,
                reason=f"Action {finding.proposed_action} not enabled for retry",
            )

        if actions_taken >= config.max_actions_per_run:
            return Decision(
                next_status=FindingStatus.FAILED,
                effect=Effect.NONE,
                reason=(
                    f"Circuit breaker reached max_actions_per_run "
                    f"({config.max_actions_per_run}); retry deferred"
                ),
            )

        return Decision(
            next_status=FindingStatus.ACTED,
            effect=Effect.ATTEMPT_ACTION,
            reason=f"Retry attempt {state.attempts + 1} for failed action",
        )

    # Fallback safe decision (never reached)
    return Decision(
        next_status=state.status,
        effect=Effect.NONE,
        reason=f"Unhandled state: {state.status}",
    )

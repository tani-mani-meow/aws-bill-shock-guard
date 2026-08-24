"""Execution runner orchestrating scan, state, notify, and action phases."""

from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Mapping

from bill_shock_guard.aws import get_enabled_regions
from bill_shock_guard.detectors.registry import discover
from bill_shock_guard.engine.state_machine import decide
from bill_shock_guard.engine.store_memory import OptimisticLockError
from bill_shock_guard.interfaces import Action, Detector, Notifier, ScanContext, StateStore
from bill_shock_guard.models import (
    ActionKind,
    Decision,
    Effect,
    Finding,
    FindingState,
    FindingStatus,
    ResourceType,
)
from bill_shock_guard.notify.format import get_exemption_command


@dataclass
class RunSummary:
    """Execution summary of an engine run."""

    run_id: str
    findings_detected: int = 0
    warnings_sent: int = 0
    actions_attempted: int = 0
    actions_performed: int = 0
    actions_failed: int = 0
    actions_deferred: int = 0
    findings_resolved: int = 0
    findings_exempt: int = 0
    findings_would_act: int = 0
    findings: list[Finding] = field(default_factory=list)
    decisions: dict[str, Decision] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class EngineRunner:
    """Orchestrates scan, state evaluation, notifications, and remedial actions."""

    def __init__(
        self,
        detectors: list[Detector] | None = None,
        actions: Mapping[ActionKind, Action] | None = None,
    ) -> None:
        if detectors is None or actions is None:
            disc_detectors, disc_actions = discover()
            self.detectors = detectors if detectors is not None else disc_detectors
            self.actions = actions if actions is not None else disc_actions
        else:
            self.detectors = detectors
            self.actions = actions

        self._detector_by_type: dict[ResourceType, Detector] = {
            d.resource_type: d for d in self.detectors
        }

    def run(
        self,
        ctx: ScanContext,
        store: StateStore,
        notifier: Notifier | None = None,
    ) -> RunSummary:
        """Execute a full engine run according to all safety invariants.

        Invariants enforced:
          - I1: Never perform a mutating AWS call when dry_run is true.
          - I2: Never act on a resource unless a warning was successfully delivered
                and recorded at least grace_hours earlier.
          - I3: Never act on a protected resource (rechecked right before action).
          - I4: Immediately before any action, re-check that single resource.
          - I5: Only perform actions listed in enabled_actions.
          - I7: Circuit breaker: at most max_actions_per_run mutating actions per run.
          - I8: Idempotent execution: no duplicate warnings or duplicate actions.
          - I9: Unknown is not idle: missing metrics/API error skips action; one failing
                region/detector never aborts others.
          - I10: Adding protect tag cancels pending action.
        """
        now = ctx.clock.now()
        summary = RunSummary(run_id=ctx.run_id)

        # -------------------------------------------------------------
        # Phase 1: Scan across enabled regions and detectors
        # -------------------------------------------------------------
        regions = self._resolve_regions(ctx, summary)
        all_findings: list[Finding] = []
        completed_scopes: set[tuple[str, str]] = set()

        for region in regions:
            for detector in self.detectors:
                scan_errors: list[str] = []
                try:
                    scan_ctx = replace(ctx, on_scan_error=scan_errors.append)
                    all_findings.extend(detector.detect(scan_ctx, region))
                except Exception as exc:
                    scan_errors.append(str(exc))
                if scan_errors:
                    error = "; ".join(scan_errors)
                    ctx.logger.error(
                        "detector_scan_failure",
                        region=region,
                        detector=detector.__class__.__name__,
                        error=error,
                    )
                    summary.errors.append(
                        f"Detector {detector.__class__.__name__} failed in region {region}: {error}"
                    )
                elif isinstance(detector.resource_type, ResourceType):
                    completed_scopes.add((region, detector.resource_type.value))

        summary.findings = all_findings
        summary.findings_detected = len(all_findings)

        # -------------------------------------------------------------
        # Phase 2: State Evaluation
        # -------------------------------------------------------------
        try:
            open_states = store.list_open()
        except Exception as exc:
            ctx.logger.error("store_list_open_failure", error=str(exc))
            summary.errors.append(f"State store list_open failed: {exc}")
            return summary

        states_by_key: dict[str, FindingState] = {s.key: s for s in open_states}
        findings_by_key: dict[str, Finding] = {f.key: f for f in all_findings}

        all_keys = set(findings_by_key.keys()) | set(states_by_key.keys())
        decisions: dict[str, Decision] = {}

        candidate_actions: list[tuple[Finding, FindingState]] = []
        new_warnings_to_deliver: list[Finding] = []
        topic_arn = ctx.config.notify.sns_topic_arn

        for key in sorted(all_keys):
            finding = findings_by_key.get(key)
            state = states_by_key.get(key)
            if state is None:
                try:
                    state = store.get(key)
                    if state is not None:
                        states_by_key[key] = state
                except Exception as exc:
                    summary.errors.append(f"Store get failed for key {key}: {exc}")
                    continue

            if state is not None and state.status == FindingStatus.ACTION_PENDING:
                summary.errors.append(f"Action outcome needs reconciliation for {state.key}")
                ctx.logger.error(
                    "action_reconciliation_required",
                    resource_key=state.key,
                    attempt_run_id=state.metadata.get("attempt_run_id"),
                )
                continue

            # Absence is meaningful only if the detector completed in that region.
            if finding is None and state is not None:
                parts = state.key.split("#", 2)
                if len(parts) != 3 or (parts[0], parts[1]) not in completed_scopes:
                    ctx.logger.warning(
                        "resolution_deferred_incomplete_scan",
                        resource_key=state.key,
                    )
                    continue

            dec = decide(
                finding=finding,
                state=state,
                now=now,
                config=ctx.config,
                actions_taken=summary.actions_performed,
            )
            if (
                finding is not None
                and state is not None
                and not finding.protected
                and not ctx.config.dry_run
                and topic_arn
                and finding.proposed_action in ctx.config.enabled_actions
                and state.status
                in {
                    FindingStatus.WARNED,
                    FindingStatus.WOULD_ACT,
                    FindingStatus.FAILED,
                }
                and state.attempts < 3
            ):
                action = finding.proposed_action
                assert action is not None
                if (
                    state.status == FindingStatus.WOULD_ACT
                    or state.warned_at is None
                    or state.metadata.get("warning_action") != action.value
                    or state.metadata.get("warning_topic_arn") != topic_arn
                ):
                    dec = Decision(
                        FindingStatus.DETECTED,
                        Effect.SEND_WARNING,
                        "Active warning required for this action and SNS topic",
                    )
                elif dec.effect == Effect.ATTEMPT_ACTION and now < state.warned_at + timedelta(
                    hours=ctx.config.grace_hours
                ):
                    dec = Decision(
                        state.status, Effect.NONE, "Current grace period is still active"
                    )
            decisions[key] = dec

            # Partition decisions
            if dec.next_status == FindingStatus.RESOLVED:
                if state is not None and state.status != FindingStatus.RESOLVED:
                    state.status = FindingStatus.RESOLVED
                    state.last_seen = now
                    state.ttl = int(now.timestamp()) + (30 * 86400)
                    state.version += 1
                    self._safe_put(store, state, summary, ctx)
                    summary.findings_resolved += 1

            elif dec.next_status == FindingStatus.EXEMPT:
                if state is None:
                    assert finding is not None
                    state = FindingState(
                        key=finding.key,
                        status=FindingStatus.EXEMPT,
                        first_seen=now,
                        last_seen=now,
                        ttl=int(now.timestamp()) + (30 * 86400),
                        version=1,
                    )
                else:
                    state.status = FindingStatus.EXEMPT
                    state.last_seen = now
                    state.ttl = int(now.timestamp()) + (30 * 86400)
                    state.version += 1
                self._safe_put(store, state, summary, ctx)
                summary.findings_exempt += 1

            elif dec.next_status == FindingStatus.WOULD_ACT:
                prior_status = state.status if state is not None else None
                if state is None and finding is not None:
                    state = FindingState(
                        key=finding.key,
                        status=FindingStatus.WOULD_ACT,
                        first_seen=now,
                        last_seen=now,
                        ttl=int(now.timestamp()) + (30 * 86400),
                        version=1,
                    )
                elif state is not None:
                    state.status = FindingStatus.WOULD_ACT
                    state.last_seen = now
                    state.ttl = int(now.timestamp()) + (30 * 86400)
                    state.version += 1
                if state is not None:
                    self._safe_put(store, state, summary, ctx)
                if prior_status != FindingStatus.WOULD_ACT:
                    summary.findings_would_act += 1

            elif dec.effect == Effect.SEND_WARNING:
                assert finding is not None
                if state is None:
                    state = FindingState(
                        key=finding.key,
                        status=FindingStatus.DETECTED,
                        first_seen=now,
                        last_seen=now,
                        version=1,
                    )
                    if not self._safe_put(store, state, summary, ctx):
                        continue
                elif state.status != FindingStatus.DETECTED:
                    state = replace(
                        state,
                        status=FindingStatus.DETECTED,
                        warned_at=None,
                        action_deadline=None,
                        ttl=None,
                        last_seen=now,
                        attempts=(
                            0
                            if state.status in {FindingStatus.EXEMPT, FindingStatus.RESOLVED}
                            else state.attempts
                        ),
                        version=state.version + 1,
                    )
                    if not self._safe_put(store, state, summary, ctx):
                        continue
                states_by_key[key] = state
                new_warnings_to_deliver.append(finding)

            elif dec.effect == Effect.ATTEMPT_ACTION and topic_arn and not ctx.config.dry_run:
                assert finding is not None and state is not None
                if state.attempts < 3:
                    candidate_actions.append((finding, state))

        summary.decisions = decisions

        # -------------------------------------------------------------
        # Phase 3: Action Execution (with live I3, I4, I9 re-verification)
        # -------------------------------------------------------------
        for finding, state in candidate_actions:
            # Circuit breaker check (Invariant I7: total attempted mutating actions)
            if summary.actions_attempted >= ctx.config.max_actions_per_run:
                summary.actions_deferred += 1
                ctx.logger.warning(
                    "circuit_breaker_deferred",
                    resource_key=finding.key,
                    max_actions=ctx.config.max_actions_per_run,
                )
                continue

            # Recheck live resource state (Invariants I3, I4, I9)
            target_detector = self._detector_by_type.get(finding.resource_type)
            if target_detector is None:
                ctx.logger.error("detector_missing_for_recheck", resource_key=finding.key)
                summary.errors.append(f"No detector for resource type {finding.resource_type}")
                continue

            try:
                recheck_res = target_detector.recheck(ctx, finding)
            except Exception as exc:
                # Invariant I9: Unknown is not idle. API error skips action.
                ctx.logger.error(
                    "recheck_api_error_unknown",
                    resource_key=finding.key,
                    error=str(exc),
                )
                summary.errors.append(f"Recheck failed for {finding.key}: {exc}")
                continue

            # Invariant I3: Protected resource
            if recheck_res.protected:
                ctx.logger.info(
                    "recheck_protected_skipping_action",
                    resource_key=finding.key,
                    reason=recheck_res.reason,
                )
                state.status = FindingStatus.EXEMPT
                state.ttl = int(now.timestamp()) + (30 * 86400)
                state.last_seen = now
                state.version += 1
                self._safe_put(store, state, summary, ctx)
                summary.findings_exempt += 1
                continue

            # Invariant I9: Unknown state is NOT idle
            if recheck_res.still_idle is None:
                ctx.logger.warning(
                    "recheck_unknown_skipping_action",
                    resource_key=finding.key,
                    reason=recheck_res.reason,
                )
                summary.errors.append(
                    f"Recheck inconclusive for {finding.key}: {recheck_res.reason}"
                )
                continue

            # Resource is no longer idle
            if not recheck_res.still_idle:
                ctx.logger.info(
                    "recheck_not_idle_skipping_action",
                    resource_key=finding.key,
                    reason=recheck_res.reason,
                )
                state.status = FindingStatus.RESOLVED
                state.ttl = int(now.timestamp()) + (30 * 86400)
                state.last_seen = now
                state.version += 1
                self._safe_put(store, state, summary, ctx)
                summary.findings_resolved += 1
                continue

            action = finding.proposed_action
            assert action is not None
            action_handler = self.actions.get(action)
            if action_handler is None:
                ctx.logger.error(
                    "action_handler_missing",
                    resource_key=finding.key,
                    action=str(finding.proposed_action),
                )
                summary.errors.append(f"Action handler missing for {finding.proposed_action}")
                continue

            # Persist intent before calling AWS. An uncertain outcome must never be replayed.
            pending = replace(
                state,
                status=FindingStatus.ACTION_PENDING,
                last_seen=ctx.clock.now(),
                attempts=state.attempts + 1,
                ttl=None,
                version=state.version + 1,
                metadata={
                    **state.metadata,
                    "attempt_run_id": ctx.run_id,
                    "attempt_action": action.value,
                },
            )
            if not self._safe_put(store, pending, summary, ctx):
                continue
            summary.actions_attempted += 1
            try:
                act_result = action_handler.apply(ctx, finding)
            except Exception as exc:
                summary.actions_failed += 1
                summary.errors.append(f"Action outcome unknown for {finding.key}: {exc}")
                ctx.logger.error(
                    "action_outcome_unknown",
                    resource_key=finding.key,
                    error=str(exc),
                )
                continue

            if act_result.needs_reconciliation:
                summary.actions_failed += 1
                detail = act_result.detail
                summary.errors.append(f"Action outcome needs reconciliation for {finding.key}")
                ctx.logger.error("action_outcome_unknown", resource_key=finding.key, error=detail)
                continue

            state = pending
            state.last_seen = ctx.clock.now()
            state.version += 1
            if act_result.ok and act_result.performed:
                state.status = FindingStatus.ACTED
                state.ttl = int(state.last_seen.timestamp()) + (30 * 86400)
                state.last_error = None
                self._safe_put(store, state, summary, ctx)
                summary.actions_performed += 1
                ctx.logger.info(
                    "action_success",
                    resource_key=finding.key,
                    detail=act_result.detail,
                )
            else:
                summary.actions_failed += 1
                state.status = FindingStatus.FAILED
                state.last_error = act_result.error or act_result.detail
                if state.attempts >= 3:
                    state.ttl = int(state.last_seen.timestamp()) + (30 * 86400)
                self._safe_put(store, state, summary, ctx)
                summary.errors.append(f"Action failed for {finding.key}: {state.last_error}")
                ctx.logger.error(
                    "action_failure",
                    resource_key=finding.key,
                    error=state.last_error,
                    attempts=state.attempts,
                )

        # -------------------------------------------------------------
        # Phase 4: Notification Digest (Single digest on events)
        # -------------------------------------------------------------
        has_notifiable_events = bool(
            new_warnings_to_deliver
            or summary.actions_performed > 0
            or summary.actions_failed > 0
            or summary.actions_deferred > 0
            or (summary.findings_would_act > 0 and ctx.config.dry_run)
        )

        if has_notifiable_events and notifier is not None:
            subject, body = self._render_digest(summary, new_warnings_to_deliver, ctx)
            try:
                delivery_ok = notifier.send(subject, body)
            except Exception as exc:
                ctx.logger.error("notifier_send_exception", error=str(exc))
                delivery_ok = False
                summary.errors.append(f"Notifier exception: {exc}")

            if delivery_ok:
                warned_at = ctx.clock.now()
                for f in new_warnings_to_deliver:
                    st = states_by_key[f.key]
                    metadata = {
                        k: v
                        for k, v in st.metadata.items()
                        if k not in {"warning_action", "warning_topic_arn"}
                    }
                    action = f.proposed_action
                    if not ctx.config.dry_run and action in ctx.config.enabled_actions:
                        assert action is not None
                        metadata.update(warning_action=action.value, warning_topic_arn=topic_arn)
                    warned = replace(
                        st,
                        status=FindingStatus.WARNED,
                        warned_at=warned_at,
                        action_deadline=warned_at + timedelta(hours=ctx.config.grace_hours),
                        last_seen=warned_at,
                        version=st.version + 1,
                        metadata=metadata,
                    )
                    if self._safe_put(store, warned, summary, ctx):
                        summary.warnings_sent += 1
                ctx.logger.info("digest_accepted", warnings_recorded=summary.warnings_sent)
            else:
                if topic_arn:
                    summary.errors.append("SNS digest could not be confirmed")
                ctx.logger.warning(
                    "digest_delivery_unconfirmed",
                    warnings=len(new_warnings_to_deliver),
                )
        elif not has_notifiable_events:
            ctx.logger.info("all_quiet_run_no_digest_needed")

        return summary

    def _resolve_regions(self, ctx: ScanContext, summary: RunSummary) -> list[str]:
        try:
            regions = list(get_enabled_regions(target_regions=ctx.config.regions, strict=True))
            if not regions:
                summary.errors.append("Region discovery returned no configured enabled regions")
            return regions
        except Exception as exc:
            ctx.logger.warning("region_discovery_error", error=str(exc))
            summary.errors.append(f"Region discovery failed: {exc}")
            if ctx.config.regions and ctx.config.regions != ["*"]:
                return list(ctx.config.regions)
            return []

    def _safe_put(
        self,
        store: StateStore,
        state: FindingState,
        summary: RunSummary,
        ctx: ScanContext,
    ) -> bool:
        try:
            store.put(state)
            return True
        except OptimisticLockError as exc:
            ctx.logger.warning(
                "optimistic_lock_conflict",
                resource_key=state.key,
                version=state.version,
            )
            summary.errors.append(f"Optimistic concurrency conflict on {state.key}: {exc}")
        except Exception as exc:
            ctx.logger.error(
                "store_put_error",
                resource_key=state.key,
                error=str(exc),
            )
            summary.errors.append(f"Store put failed on {state.key}: {exc}")
        return False

    def _render_digest(
        self,
        summary: RunSummary,
        new_warnings: list[Finding],
        ctx: ScanContext,
    ) -> tuple[str, str]:
        prefix = "DRY RUN: " if ctx.config.dry_run else ""
        subject = (
            f"{prefix}Bill Shock Guard: {len(new_warnings)} warning(s), "
            f"{summary.actions_performed} action(s)"
        )

        lines = [
            f"Bill Shock Guard Digest - Run ID: {ctx.run_id}",
            f"Dry Run: {ctx.config.dry_run}",
            f"Time (UTC): {ctx.clock.now().isoformat()}",
            "",
        ]

        if ctx.config.dry_run:
            lines.append("DRY RUN: nothing will be changed.")
            lines.append("")

        if new_warnings:
            lines.append(f"--- New Warnings ({len(new_warnings)}) ---")
            for f in new_warnings:
                cost_str = (
                    f"${f.est_monthly_cost_usd:.2f}/mo"
                    if f.est_monthly_cost_usd is not None
                    else "unknown"
                )
                lines.append(f"- {f.resource_type.value} {f.resource_id} in {f.region}")
                lines.append(f"  Reason: {f.reason}")
                lines.append(f"  Est Monthly Cost: {cost_str} ({f.cost_confidence})")
                action = f.proposed_action
                if action in ctx.config.enabled_actions:
                    lines.append(f"  Proposed Action: {action}")
                    lines.append(f"  Grace period: {ctx.config.grace_hours} hour(s)")
                else:
                    lines.append("  Proposed Action: none (alert only)")
                resource_id = str(f.evidence.get("resource_arn") or f.resource_id)
                if f.resource_type in {
                    ResourceType.RDS_INSTANCE,
                    ResourceType.SAGEMAKER_NOTEBOOK,
                } and not resource_id.startswith("arn:"):
                    lines.append(f"  Exempt by adding tag {ctx.config.protect_tag_key}=true.")
                else:
                    command = get_exemption_command(
                        f.resource_type, resource_id, f.region, tag_key=ctx.config.protect_tag_key
                    )
                    lines.append(f"  Exempt with: {command}")
                lines.append("")

        if summary.actions_performed > 0:
            lines.append(f"--- Actions Performed ({summary.actions_performed}) ---")
            lines.append(f"Total performed: {summary.actions_performed}")
            lines.append("")

        if summary.actions_failed > 0:
            lines.append(f"--- Actions Failed ({summary.actions_failed}) ---")
            lines.append(f"Total failed: {summary.actions_failed}")
            lines.append("")

        if summary.actions_deferred > 0:
            lines.append(f"--- Circuit Breaker Deferred ({summary.actions_deferred}) ---")
            lines.append(
                "Actions deferred to next run due to max_actions_per_run limit "
                f"({ctx.config.max_actions_per_run})."
            )
            lines.append("")

        return subject, "\n".join(lines)


def run_engine(
    ctx: ScanContext,
    store: StateStore,
    notifier: Notifier | None = None,
    detectors: list[Detector] | None = None,
    actions: Mapping[ActionKind, Action] | None = None,
) -> RunSummary:
    """Convenience function to instantiate EngineRunner and run a cycle."""
    runner = EngineRunner(detectors=detectors, actions=actions)
    return runner.run(ctx, store, notifier=notifier)

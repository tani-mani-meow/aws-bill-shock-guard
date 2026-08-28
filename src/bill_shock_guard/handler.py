"""AWS Lambda entry point for Bill Shock Guard."""

import os
import uuid
from typing import Any, Mapping

from bill_shock_guard.aws import get_boto_client
from bill_shock_guard.clock import SystemClock
from bill_shock_guard.config import Config, load_config_from_json
from bill_shock_guard.engine.runner import EngineRunner, RunSummary
from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import ScanContext, StateStore
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.notify.composite import CompositeNotifier


def _get_account_id(context: Any, current_region: str) -> str:
    """Extract account ID from Lambda context ARN or fallback to STS caller identity."""
    invoked_arn = getattr(context, "invoked_function_arn", None)
    if invoked_arn and isinstance(invoked_arn, str):
        parts = invoked_arn.split(":")
        if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
            return parts[4]

    try:
        sts = get_boto_client("sts", region_name=current_region)
        resp = sts.get_caller_identity()
        return str(resp.get("Account", "123456789012"))
    except Exception:
        return "123456789012"


def _build_state_store(config: Config, region: str) -> StateStore:
    """Build DynamoDbStateStore if state_table configured, otherwise MemoryStateStore."""
    if config.state_table:
        client = get_boto_client("dynamodb", region_name=region)
        return DynamoDbStateStore(table_name=config.state_table, client=client)
    return MemoryStateStore()


def scan_handler(event: Mapping[str, Any] | None = None, context: Any = None) -> dict[str, Any]:
    """Lambda execution handler for scheduled scans.

    Builds configuration from environment variable BSG_CONFIG, creates state store
    and notifiers, runs the engine lifecycle, and returns a JSON counts summary.
    """
    raw_env_config = os.environ.get("BSG_CONFIG")
    if raw_env_config and raw_env_config.strip():
        config = load_config_from_json(raw_env_config)
    else:
        config = Config()

    region = os.environ.get("AWS_REGION", "us-east-1")
    raw_req_id = getattr(context, "aws_request_id", None)
    run_id = f"run-{raw_req_id}" if raw_req_id else f"run-{uuid.uuid4().hex[:12]}"

    logger = JsonLogger(run_id=run_id, region=region)
    logger.info("lambda_scan_started", region=region, dry_run=config.dry_run)

    account_id = _get_account_id(context, region)
    clock = SystemClock()

    ctx = ScanContext(
        config=config,
        clock=clock,
        account_id=account_id,
        run_id=run_id,
        logger=logger,
        client_factory=get_boto_client,
    )

    store = _build_state_store(config, region)
    notifier = CompositeNotifier.from_config(config, logger=logger)

    runner = EngineRunner()
    summary: RunSummary = runner.run(ctx, store, notifier=notifier)

    logger.info(
        "lambda_scan_completed",
        findings_detected=summary.findings_detected,
        warnings_sent=summary.warnings_sent,
        actions_performed=summary.actions_performed,
        actions_failed=summary.actions_failed,
        actions_deferred=summary.actions_deferred,
        findings_resolved=summary.findings_resolved,
        errors_count=len(summary.errors),
    )

    return {
        "status": "success" if not summary.errors else "completed_with_errors",
        "run_id": run_id,
        "counts": {
            "findings_detected": summary.findings_detected,
            "warnings_sent": summary.warnings_sent,
            "actions_attempted": summary.actions_attempted,
            "actions_performed": summary.actions_performed,
            "actions_failed": summary.actions_failed,
            "actions_deferred": summary.actions_deferred,
            "findings_resolved": summary.findings_resolved,
            "findings_exempt": summary.findings_exempt,
            "findings_would_act": summary.findings_would_act,
            "errors": len(summary.errors),
        },
    }

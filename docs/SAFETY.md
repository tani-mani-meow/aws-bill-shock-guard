# Safety Invariants and Enforcement

Author: Tanishq Ingawale (MIT License)

When building Bill Shock Guard, my primary fear was creating a tool that causes more damage than the cloud bills it was designed to prevent. An automated tool with permission to stop compute instances or release IP addresses can disrupt active coursework, student research, or running services if its decision logic is flawed.

To eliminate reckless behavior, Bill Shock Guard operates under ten non-negotiable safety invariants (I1 to I10). Every invariant is implemented with defense-in-depth: logic checks in the pure state machine, live runtime guards in the execution runner, and matching constraints in AWS IAM policies.

---

## 1. Safety Invariants (I1 to I10)

### Invariant I1: Never perform a mutating AWS call when `dry_run` is true
- **Description**: In dry run mode, the tool acts strictly as a reporter. It scans resources, computes estimated costs, updates tracking states to `WOULD_ACT`, and delivers warning digests. It is programmatically impossible for a mutating AWS SDK call to execute.
- **Enforcement Mechanisms**:
  1. Strict boolean validation in configuration loading rejects truthy string coercion (e.g. `"false"` or `0` raise `ValueError`).
  2. Pure state machine transitions findings to `WOULD_ACT` with `effect=Effect.NONE`.
  3. Execution runner verifies `if ctx.config.dry_run:` before evaluating action candidates.
  4. Every individual action class (`ec2.py`, `eip.py`, `nat.py`, `ebs.py`, `elb.py`, `rds.py`, `sagemaker.py`) checks `ctx.config.dry_run` internally before issuing AWS SDK calls.
- **Enforcing Tests**:
  - `tests/adversarial/test_malformed_config.py::test_strict_dry_run_type_coercion_rejected`
  - `tests/engine/test_state_machine.py::test_I1_dry_run_never_acts_property`
  - `tests/engine/test_runner.py::test_I1_dry_run_never_mutates`
  - `tests/detectors/test_ec2.py::test_I1_ec2_stop_dry_run_does_not_mutate`
  - `tests/detectors/test_eip.py::test_I1_eip_release_dry_run_does_not_mutate`
  - `tests/detectors/test_nat.py::test_I1_nat_delete_dry_run_no_mutation`
  - `tests/detectors/test_ebs.py::test_I1_ebs_dry_run_never_mutates`
  - `tests/detectors/test_elb.py::test_I1_elb_delete_dry_run_no_mutation`
  - `tests/detectors/test_rds.py::test_I1_rds_dry_run_never_mutates`
  - `tests/detectors/test_sagemaker.py::test_I1_sagemaker_dry_run_never_mutates`

### Invariant I2: Record an active-mode warning before starting the grace period
- The SNS notifier checks for a confirmed email subscription before publishing. The SNS acknowledgment means the topic accepted the message. Inbox delivery is asynchronous.
- The runner records the acknowledgment time and grace deadline in DynamoDB, together with the enabled action and topic ARN. Dry-run warnings and older records without this metadata require a fresh active-mode warning. A changed action or topic also requires a fresh warning.
- **Enforcement Mechanisms**:
  1. The runner requires the recorded deadline and current grace period to have elapsed.
  2. A failed subscription lookup, publish, or warning state write leaves the finding ineligible for action.
- **Enforcing Tests**:
  - `tests/engine/test_state_machine.py::test_I2_grace_and_warning_required_property`
  - `tests/engine/test_runner.py::test_I2_warning_delivery_required_for_action`
  - `tests/notify/test_composite.py::test_I2_delivery_confirmed_semantics`
  - `tests/adversarial/test_backwards_clock.py::test_clock_moves_backwards_before_warned_at`
  - `tests/adversarial/test_backwards_clock.py::test_clock_moves_backwards_from_expired_to_unexpired_deadline`
  - `tests/adversarial/test_huge_digests.py::test_telegram_notifier_fails_if_any_chunk_fails`

### Invariant I3: Never act on a protected resource
- **Description**: Any resource flagged as protected is never touched. Protection applies if the resource is explicitly listed in `ignore_resource_ids`, tagged with the protect key (`bsg:keep`), or managed by cloud automation (Auto Scaling groups, Elastic Beanstalk, Amazon EKS).
- **Enforcement Mechanisms**:
  1. Protection tag inspection supports boolean values (`true`, `yes`, `1`) and future ISO expiration dates (`YYYY-MM-DD`).
  2. Protection re-verification occurs both during detector discovery and live immediately prior to action execution.
  3. Malformed tag formats, empty strings, or impossible dates fail closed by treating the resource as protected.
- **Enforcing Tests**:
  - `tests/test_protection.py::test_I3_protected_by_keep_true_tag`
  - `tests/test_protection.py::test_I3_protected_by_ignore_resource_ids`
  - `tests/test_protection.py::test_I3_protected_by_keep_date_future`
  - `tests/test_protection.py::test_I3_fail_closed_on_invalid_date_format`
  - `tests/test_protection.py::test_I3_fail_closed_on_invalid_calendar_date`
  - `tests/test_protection.py::test_I3_protected_by_managed_tag`
  - `tests/engine/test_runner.py::test_I3_protected_resource_never_acted_on`
  - `tests/detectors/test_ec2.py::test_I3_ec2_detect_protect_tag_returns_protected_finding`
  - `tests/detectors/test_eip.py::test_I3_eip_detect_protected_by_tag`
  - `tests/detectors/test_nat.py::test_I3_nat_detector_protect_tag`
  - `tests/detectors/test_ebs.py::test_I3_ebs_protected_resource`
  - `tests/detectors/test_elb.py::test_I3_elb_detector_protect_tag`
  - `tests/detectors/test_rds.py::test_I3_rds_protected_resource`
  - `tests/detectors/test_sagemaker.py::test_I3_sagemaker_protected_notebook`
  - `tests/adversarial/test_odd_tags.py::test_tag_value_empty_or_whitespace_fails_closed`
  - `tests/adversarial/test_odd_tags.py::test_tag_value_invalid_date_or_calendar_fails_closed`

### Invariant I4: Immediately before any action, re-check that single resource
- **Description**: Stored finding states can become stale between 6-hour scan cycles. Immediately before applying a mutating action, the runner issues live AWS API calls against the target resource to verify status, protection tags, and CloudWatch activity metrics. If the resource was restarted, acquired network traffic, or was deleted, the action aborts immediately.
- **Enforcement Mechanisms**:
  1. Every detector implements `recheck(ctx, finding) -> RecheckResult`.
  2. EC2, NAT gateways, Application Load Balancers, and SageMaker notebooks re-query CloudWatch metrics during recheck.
  3. If traffic or CPU utilization exceeds idle thresholds during the recheck window, `still_idle` evaluates to `False`, and state transitions to `RESOLVED`.
- **Enforcing Tests**:
  - `tests/engine/test_runner.py::test_I4_recheck_before_action_aborts_if_not_idle`
  - `tests/detectors/test_ec2.py::test_I4_ec2_recheck_detects_activity_and_blocks_action`
  - `tests/detectors/test_eip.py::test_I4_eip_recheck_detects_association_and_blocks_action`
  - `tests/detectors/test_nat.py::test_I4_nat_recheck_traffic_arrived_not_idle`
  - `tests/detectors/test_ebs.py::test_I4_ebs_recheck_detects_state_change`
  - `tests/detectors/test_elb.py::test_I4_elb_recheck_traffic_arrived_blocks_action`
  - `tests/detectors/test_rds.py::test_I4_rds_recheck`
  - `tests/detectors/test_sagemaker.py::test_I4_sagemaker_recheck_active_notebook_blocks_action`

### Invariant I5: Only perform actions listed in `enabled_actions`
- **Description**: Bill Shock Guard will never execute an action that is not explicitly enabled in configuration. Furthermore, Terraform generates IAM policies dynamically: actions omitted from `var.enabled_actions` receive zero IAM permissions in the deployed Lambda role.
- **Enforcement Mechanisms**:
  1. The state machine checks `finding.proposed_action not in config.enabled_actions` and refuses to yield `ATTEMPT_ACTION`.
  2. Terraform `iam.tf` dynamically maps `var.enabled_actions` to IAM action strings; unselected actions are entirely omitted from policy statements.
- **Enforcing Tests**:
  - `tests/engine/test_runner.py::test_I5_disabled_action_not_performed`
  - `tests/test_iam_matches_code.py::test_iam_actions_cover_all_boto3_methods`
  - `tests/adversarial/test_malformed_config.py::test_invalid_enabled_actions_rejected`

### Invariant I6: Default configuration never terminates instances and never deletes data; EBS deletion requires a completed snapshot
- **Description**: The default configuration permits only non-destructive actions (`ec2_stop` and `eip_release`). Deleting NAT gateways, deleting load balancers, or removing EBS volumes requires explicit opt-in. If EBS volume deletion is enabled, Bill Shock Guard creates a snapshot and polls AWS until snapshot completion is verified before calling `DeleteVolume`.
- **Enforcement Mechanisms**:
  1. Default `Config().enabled_actions` contains strictly `[ActionKind.EC2_STOP, ActionKind.EIP_RELEASE]`.
  2. `EBSDeleteAfterSnapshotAction` requires status `completed` on `DescribeSnapshots`. If snapshot creation fails, times out, or throws an error, volume deletion is aborted.
- **Enforcing Tests**:
  - `tests/test_config.py::test_default_config_enabled_actions`
  - `tests/detectors/test_ebs.py::test_I6_ebs_delete_requires_completed_snapshot`
  - `tests/detectors/test_ebs.py::test_I6_snapshot_failure_prevents_volume_deletion`
  - `tests/detectors/test_ebs.py::test_I6_snapshot_error_prevents_volume_deletion`
  - `tests/detectors/test_ebs.py::test_I6_snapshot_timeout_prevents_volume_deletion`

### Invariant I7: Circuit breaker limits mutating actions to at most `max_actions_per_run`
- **Description**: To prevent run-away automation or massive batch deletions during unexpected account changes, the engine halts mutating actions once `max_actions_per_run` (default 5) actions are attempted.
- **Enforcement Mechanisms**:
  1. The circuit breaker counts attempts once the action claim is persisted and the runner calls the action handler.
  2. Remaining candidate actions are deferred to the next scheduled run.
- **Enforcing Tests**:
  - `tests/engine/test_state_machine.py::test_I7_circuit_breaker_property`
  - `tests/engine/test_runner.py::test_I7_circuit_breaker_max_actions`
  - `tests/adversarial/test_malformed_config.py::test_invalid_max_actions_per_run_rejected`

### Invariant I8: Persist action intent before calling AWS
- The runner uses a conditional DynamoDB write to claim an action as `ACTION_PENDING`. A failed claim prevents the call. A successful claim records the run ID, action, and attempt count.
- The runner records `ACTED` after success and `FAILED` after a known failure. A failed outcome write, interrupted invocation, or ambiguous AWS response leaves the claim pending. Later scans report it for operator reconciliation and skip the action. A warning may be resent if SNS accepted it and DynamoDB failed to record it.
- **Enforcement Mechanisms**:
  1. DynamoDB checks the previous `version` on each write.
  2. The [verification guide](VERIFICATION.md#reconcile-a-pending-action) covers pending claims.
- **Enforcing Tests**:
  - `tests/engine/test_state_machine.py::test_I8_idempotence_property`
  - `tests/engine/test_runner.py::test_I8_idempotent_no_duplicate_warning_or_action`
  - `tests/engine/test_end_to_end.py::test_end_to_end_lifecycle`
  - `tests/adversarial/test_backwards_clock.py::test_runner_multi_cycle_with_backwards_clock`

### Invariant I9: Unknown is not idle. A failure in one region never aborts others
- **Description**: If CloudWatch returns empty datapoints, an API call is throttled, or an AWS service returns an error, the resource is treated as active and unknown. The engine never assumes missing metrics imply zero traffic. Furthermore, an API outage in one region is contained to that region and never halts scanning in healthy regions.
- **Enforcement Mechanisms**:
  1. Recheck functions return `still_idle=None` on missing metrics or API errors; the runner skips actions on `None`.
  2. The regional loop wraps detector executions in isolated try/except blocks.
  3. A missing finding is resolved only after its detector completes successfully in its region. A failed discovery or detector scan preserves prior findings in unscanned scopes. The CloudWatch scan-errors alarm also covers partial results returned successfully by Lambda.
- **Enforcing Tests**:
  - `tests/engine/test_runner.py::test_I9_unknown_is_not_idle_and_per_detector_isolation`
  - `tests/detectors/test_ec2.py::test_I9_ec2_missing_metrics_synthetic`
  - `tests/detectors/test_ec2.py::test_I9_ec2_recheck_missing_metrics_returns_none`
  - `tests/detectors/test_eip.py::test_I9_eip_recheck_api_error_returns_none`
  - `tests/detectors/test_nat.py::test_I9_nat_detector_no_metrics_ignored`
  - `tests/detectors/test_nat.py::test_I9_nat_recheck_missing_metrics_returns_unknown`
  - `tests/detectors/test_ebs.py::test_I9_ebs_api_failure_returns_unknown`
  - `tests/detectors/test_elb.py::test_I9_elb_recheck_missing_metrics_returns_unknown`
  - `tests/detectors/test_rds.py::test_I9_rds_missing_metrics_not_idle`
  - `tests/detectors/test_sagemaker.py::test_I9_sagemaker_notebook_missing_metrics_not_detected`
  - `tests/detectors/test_sagemaker.py::test_I9_sagemaker_recheck_missing_metrics_returns_none`
  - `tests/adversarial/test_region_failures.py::test_I9_describe_regions_client_error_fallback`
  - `tests/adversarial/test_region_failures.py::test_I9_one_region_fails_does_not_abort_other_regions`
  - `tests/adversarial/test_region_failures.py::test_I9_recheck_api_error_skips_action`
  - `tests/adversarial/test_region_failures.py::test_I9_recheck_unknown_idle_status_skips_action`

### Invariant I10: Adding a protect tag after warning cancels pending actions
- **Description**: A student who receives a warning digest can exempt their resource at any point during the 24-hour grace period simply by tagging it with `bsg:keep=true`.
- **Enforcement Mechanisms**:
  1. Live recheck right before action execution checks current tags.
  2. If the protect tag is detected, the pending action is immediately aborted and the state transitions to `EXEMPT`.
  3. The IAM execution policy includes an explicit `Deny` condition keyed on `aws:ResourceTag/bsg:keep`.
- **Enforcing Tests**:
  - `tests/engine/test_runner.py::test_I10_protect_tag_cancels_pending_action`
  - `tests/detectors/test_ec2.py::test_I10_ec2_recheck_race_tag_added_after_warning`
  - `tests/detectors/test_eip.py::test_I10_eip_recheck_race_tag_added_after_warning`
  - `tests/detectors/test_nat.py::test_I3_I10_nat_recheck_protected_tag_added`

---

## 2. IAM Tag Condition and Deny Block Architecture

To prevent accidental modification of protected resources even in the event of an application logic bug, Terraform configures an explicit `Deny` block in `terraform/modules/guard/iam.tf`.

### Verified IAM Actions Supporting Tag Conditions

We verified each candidate mutating action against the official AWS IAM Service Authorization Reference to confirm which actions support resource-level permissions and the `aws:ResourceTag/${TagKey}` condition key:

| Mutating Action | AWS Resource Type ARN | Supports Resource-Level? | Supports `aws:ResourceTag`? |
|---|---|---|---|
| `ec2:StopInstances` | `arn:aws:ec2:*:*:instance/*` | Yes | Yes |
| `ec2:ReleaseAddress` | `arn:aws:ec2:*:*:elastic-ip/*` | Yes | Yes |
| `ec2:DeleteNatGateway` | `arn:aws:ec2:*:*:natgateway/*` | Yes | Yes |
| `ec2:DeleteVolume` | `arn:aws:ec2:*:*:volume/*` | Yes | Yes |
| `elasticloadbalancing:DeleteLoadBalancer` | `arn:aws:elasticloadbalancing:*:*:loadbalancer/*` | Yes | Yes |
| `rds:StopDBInstance` | `arn:aws:rds:*:*:db:*` | Yes | Yes |
| `sagemaker:StopNotebookInstance` | `arn:aws:sagemaker:*:*:notebook-instance/*` | Yes | Yes |

Every action included in `local.tag_protectable_actions_map` natively supports resource-level tag conditions.

### Explanation of the IAM Deny Block

The policy statement in `iam.tf` is constructed as follows:

```hcl
statement {
  sid       = "DenyMutatingProtectedResources"
  effect    = "Deny"
  actions   = local.tag_protectable_mutating_actions
  resources = ["*"]

  condition {
    test     = "Null"
    variable = "aws:ResourceTag/${var.protect_tag_key}"
    values   = ["false"]
  }
}
```

In AWS IAM condition evaluation:
- The `Null` condition tests whether a tag key is absent from the target resource context.
- Setting `values = ["false"]` means: "The condition evaluates to true when the tag is NOT null (that is, the tag exists on the target resource)."
- Because an explicit `Deny` in AWS IAM always takes precedence over an `Allow`, any mutating call targeted at a resource with the `bsg:keep` tag is denied by the AWS IAM evaluation engine directly at the API boundary, regardless of application code.

---

## 3. Checkov Skips and Architectural Justifications

To achieve near-zero operating cost (< $0.05 per month), Bill Shock Guard deliberately avoids high-cost managed AWS security services. In `.checkov.yml`, specific security rules are skipped with explicit written justifications:

- **`CKV_AWS_116` (Ensure AWS Lambda function has a Dead Letter Queue)**:
  - *Justification*: Bill Shock Guard deploys a CloudWatch metric alarm that watches for Lambda execution errors (`Errors >= 1` over 6 hours) and sends alerts directly to the SNS topic. Provisioning a dedicated SQS queue or DLQ adds unnecessary setup friction and potential cost without operational benefit for a 6-hour batch job.
- **`CKV_AWS_117` (Ensure AWS Lambda function is configured inside a VPC)**:
  - *Justification*: Placing Lambda inside a VPC requires either an AWS NAT Gateway ($32.85/month in us-east-1) or dedicated VPC endpoints ($7.30/endpoint/month) to communicate with AWS public API endpoints (EC2, CloudWatch, DynamoDB, SNS). Operating the Lambda inside a VPC would create the exact recurring cloud bill the tool is designed to prevent.
- **`CKV_AWS_173` (Check Lambda environment variable is encrypted using KMS CMK)**:
  - *Justification*: The `BSG_CONFIG` environment variable contains strictly non-sensitive configuration parameters (thresholds, region lists, tag names). Any sensitive token (such as a Telegram bot token) is retrieved from AWS SSM Parameter Store at runtime. AWS KMS Customer Managed Keys (CMKs) cost $1.00 per key per month; default AWS-managed encryption is used to keep costs at zero.
- **`CKV_AWS_28` (Ensure DynamoDB point-in-time recovery is enabled)**:
  - *Justification*: The DynamoDB state table holds ephemeral finding states with a 30-day Time-To-Live (TTL). Point-in-time recovery (PITR) incurs continuous backup storage charges. If the state table were lost, the scanner would simply re-detect idle resources and start a new warning cycle.
- **`CKV_AWS_119`, `CKV_AWS_26`, `CKV_AWS_158` (Ensure DynamoDB, SNS, and CloudWatch Logs use KMS CMKs)**:
  - *Justification*: Default AWS-managed encryption (`aws/dynamodb`, `aws/sns`, `aws/logs`) is enabled across all resources at $0 cost. Customer Managed Keys are avoided to eliminate recurring monthly KMS fees.

---

## 4. Known Failure Modes and Fail-Closed Behavior

Bill Shock Guard is designed to fail closed. In any ambiguity, the system chooses to do nothing rather than risk damaging resources.

1. **Missing Metrics (CloudWatch Data Gaps)**:
   - When a resource has zero metric datapoints returned by CloudWatch, `still_idle` returns `None` (unknown). The system treats unknown as active, skipping action execution.
2. **Malformed Configuration Payload**:
   - If the `BSG_CONFIG` JSON payload contains invalid syntax, unexpected root types, or missing parameters, the Lambda scan handler aborts immediately during initialization before issuing any AWS API calls.
3. **Tag Formatting Anomalies**:
   - If a student creates a tag with whitespace, invalid date formats (`2026-02-30`), or non-date text (`tomorrow`), the parser treats the tag as valid and protected, deferring action.
4. **Detector or Regional Outages**:
   - If AWS APIs fail in one region, the runner records a regional failure. Prior findings in that region are retained in their current state and are not marked resolved.
5. **Backwards Clock Skews**:
   - If system time steps backward due to NTP synchronization, the condition `now >= action_deadline` evaluates to false, deferring action until the deadline elapses under valid time.

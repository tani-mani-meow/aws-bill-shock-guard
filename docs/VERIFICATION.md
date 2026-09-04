# Human Verification Checklist

Author: Tanishq Ingawale (MIT License)

This document provides a step-by-step verification checklist for validating Bill Shock Guard on a live AWS account.

> **Safety Notice**: Run this verification checklist strictly inside an isolated, disposable AWS account (such as an AWS Free Tier sandbox or AWS Organizations scratch account). Never run experiments in an account hosting active student projects or live workloads.

---

## Prerequisites

Before starting, ensure your local environment has the required tools configured:

1. **AWS CLI and Credentials**:
   ```bash
   aws sts get-caller-identity --query Account --output text
   ```
   Set `AWS_PROFILE` to your sandbox profile in this terminal. Confirm the
   account ID before planning, applying, or destroying infrastructure.

2. **Python and Bill Shock Guard**:
   ```bash
   bsg --version
   bsg doctor --regions us-east-1
   ```
   `bsg doctor` checks STS credentials and read access in the selected region.

3. **Terraform**:
   Ensure Terraform (>= 1.6.0) is installed.

---

## Verification Steps

### Step 1: Package the Scanner Lambda

Before deploying Terraform, package the Lambda source code into a deployable directory:

```bash
python scripts/package_lambda.py
```

This populates `build/lambda/bill_shock_guard` with the standalone Python package.

---

### Step 2: Deploy Bill Shock Guard in Dry Run Mode

Navigate to the basic Terraform deployment example:

```bash
cd terraform/examples/basic
```

Create a `terraform.tfvars` file:

```hcl
aws_region          = "us-east-1"
name_prefix         = "bsg-smoke"
dry_run             = true
notification_emails = ["your-email@example.com"]
enabled_actions     = []
```

Initialize and apply the Terraform configuration:

```bash
terraform init
terraform plan -out=../../../build/bsg-smoke.tfplan
terraform apply ../../../build/bsg-smoke.tfplan
```

Review the saved plan before applying. A fresh smoke-test stack should show only creations. An empty action allowlist omits workload mutation permissions from the Lambda role. The basic example scans all enabled regions.

> **Important**: Check your email inbox immediately for a message from AWS Notifications with the subject `AWS Notification - Subscription Confirmation`. Click the confirmation link to enable SNS alert delivery.

---

### Step 3: Allocate One Unassociated Elastic IP

```bash
aws ec2 allocate-address --domain vpc --region us-east-1 --query AllocationId --output text
```

Save the allocation ID for the scan, exemption check, and cleanup. AWS bills the
address while it is allocated. [Amazon VPC pricing](https://aws.amazon.com/vpc/pricing/)

---

### Step 4: Run a Manual Scan

Verify that Bill Shock Guard detects the unassociated Elastic IP by running a local read-only scan:

```bash
bsg scan --regions us-east-1
```

Confirm that the output table displays:
- Resource Type: `elastic_ip`
- Status: `Idle (unassociated)`
- Estimated Monthly Cost: `$3.65 USD`
- Proposed Action: `eip_release`
- Protected: `No`

---

### Step 5: Trigger the Lambda and Inspect the Notification Digest

Trigger the deployed Lambda function manually to simulate an EventBridge cycle:

```bash
aws lambda invoke \
  --function-name bsg-smoke-scan \
  --region us-east-1 \
  response.json
```

Inspect the response file:

```bash
cat response.json
```

Confirm that the invoke metadata has no `FunctionError`. In the response body,
expect `status = "success"`, `findings_detected >= 1`, `warnings_sent >= 1`,
and `actions_attempted = 0`. If a scheduled run picked up the address first,
check its email and DynamoDB record for the same allocation ID.

After confirming the SNS email subscription, check your inbox for the plain-text digest:

```text
DRY RUN: Bill Shock Guard: 1 warning(s), 0 action(s)
```

Verify the body of the email:
1. Displays the UTC timestamp and the run ID.
2. Identifies the run as a dry run.
3. Lists the Elastic IP allocation ID, region (`us-east-1`), and reason.
4. Includes the exact AWS CLI command to exempt the resource if desired.

### Reconcile a pending action

The scan-errors alarm can fire when a DynamoDB record is still `ACTION_PENDING`. Use its
`metadata.attempt_run_id`, `metadata.attempt_action`, and resource key to look up the
invocation logs, AWS CloudTrail events, and current resource state. For EBS, also check
for a snapshot tagged with the source volume ID.

If you can verify success, conditionally update the finding to `ACTED` and increment
its version. If you can verify the action had no effect and intend to retry it,
conditionally update it to `DETECTED`, clear the warning timestamps and warning
metadata, and increment the version. Reset the attempt count if you intend to
authorize a fresh set of attempts. The next scan starts a new warning and grace
period. Keep the claim pending while the outcome is uncertain.

---

### Step 6: Test Exemption Tagging (`bsg:keep=true`)

Test Invariant I10 by applying the protection tag to the test Elastic IP.

Run the tag helper script:

```bash
python scripts/tag_resource.py \
  --resource-id <your-allocation-id> \
  --region us-east-1 \
  --tag-key bsg:keep \
  --tag-value true
```

Or apply the tag with AWS CLI:

```bash
aws ec2 create-tags \
  --resources <your-allocation-id> \
  --tags Key=bsg:keep,Value=true \
  --region us-east-1
```

Re-run the scan:

```bash
bsg scan --regions us-east-1
```

Verify that the resource is now reported as protected. JSON output still shows
the detector's proposed action alongside `protected: true`.

Trigger the Lambda a second time:

```bash
aws lambda invoke \
  --function-name bsg-smoke-scan \
  --region us-east-1 \
  response.json
```

Confirm the DynamoDB item with key `us-east-1#elastic_ip#<your-allocation-id>`
changes from `WARNED` to `EXEMPT`. The second invocation should attempt zero
actions. The address should still be allocated.

---

### Step 7: Teardown and Complete Cleanup

Release the exact address you allocated, then destroy the stack from
`terraform/examples/basic` using the same sandbox profile and Terraform inputs.

```bash
aws ec2 release-address --allocation-id <your-allocation-id> --region us-east-1
terraform destroy
terraform state list
aws ec2 describe-addresses --allocation-ids <your-allocation-id> --region us-east-1
```

Check that the Terraform state lists no resources and the address lookup reports
`InvalidAllocationID.NotFound`.

# Engineering Notes

## Detecting IAM policy drift

An earlier Lambda policy omitted AWS permissions required by the load balancer and SageMaker detectors. The test that checked SDK calls against IAM also omitted those calls, so it passed despite the policy gaps. The [IAM drift test](../tests/test_iam_matches_code.py) now checks calls made by the implementation against the Terraform policies.

## Bounding remediation during API failures

An earlier implementation counted only successful actions toward the per-run limit. When AWS rejected requests, the runner could attempt more remediations than the configured limit allowed. The [runner](../src/bill_shock_guard/engine/runner.py) now counts attempts, including failed requests.

## Preserving findings during incomplete scans

A regional API failure could make an open finding disappear from a scan and start its warning grace period over when the region recovered. The runner now resolves a missing finding only after its detector completes successfully in that region. The [regional failure tests](../tests/adversarial/test_region_failures.py) exercise this behavior.

These safeguards are covered by automated tests. Live AWS validation is pending. The [verification guide](VERIFICATION.md) describes the smoke test.

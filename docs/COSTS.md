# Cost Documentation

I built Bill Shock Guard because I watched classmates in Pune run a lab assignment on AWS, forget to delete their VPC NAT gateway or stop their EC2 instances, and wake up to a $50 bill on a student budget.

This document states two sets of numbers honestly:
1. The approximate monthly cost of leaving each monitored resource type idle.
2. The running cost of Bill Shock Guard itself on your AWS account.

All cost figures are approximate estimates in USD. Prices were verified on 2026-11-12 against official AWS documentation. Baseline hours per month is 730 hours (365 days * 24 hours / 12 months).

---

## 1. Monthly Cost of Idle AWS Resources

The table below lists the approximate monthly cost of leaving a single forgotten resource running 24/7 for 730 hours. Data is verified for US East (N. Virginia, `us-east-1`), Asia Pacific (Mumbai, `ap-south-1`), and Europe (Ireland, `eu-west-1`). Other regions fall back to `us-east-1` estimates.

| Resource Type | Specification | us-east-1 (N. Virginia) | ap-south-1 (Mumbai) | eu-west-1 (Ireland) | Verified Source |
|---|---|---|---|---|---|
| NAT Gateway | 1 provisioned gateway (idle) | $32.85 | $40.88 | $35.04 | [VPC Pricing](https://aws.amazon.com/vpc/pricing/) ($0.045 / $0.056 / $0.048 per hr) |
| Elastic IP | 1 unattached public IPv4 | $3.65 | $3.65 | $3.65 | [VPC Pricing](https://aws.amazon.com/vpc/pricing/) ($0.005 per hr flat rate) |
| Application Load Balancer | 1 provisioned ALB (0 traffic) | $16.43 | $17.45 | $16.43 | [ELB Pricing](https://aws.amazon.com/elasticloadbalancing/pricing/) ($0.0225 / $0.0239 per hr) |
| EBS gp3 Volume | 8 GB root volume | $0.64 | $0.73 | $0.70 | [EBS Pricing](https://aws.amazon.com/ebs/pricing/) ($0.080 / $0.0912 / $0.088 per GB-mo) |
| EBS gp3 Volume | 20 GB unattached volume | $1.60 | $1.82 | $1.76 | [EBS Pricing](https://aws.amazon.com/ebs/pricing/) ($0.080 / $0.0912 / $0.088 per GB-mo) |
| EBS gp3 Volume | 100 GB unattached volume | $8.00 | $9.12 | $8.80 | [EBS Pricing](https://aws.amazon.com/ebs/pricing/) ($0.080 / $0.0912 / $0.088 per GB-mo) |
| EC2 Instance | t4g.nano Linux (idle) | $3.07 | $3.50 | $3.36 | [EC2 Pricing](https://aws.amazon.com/ec2/pricing/on-demand/) ($0.0042 / $0.0048 / $0.0046 per hr) |
| EC2 Instance | t3.micro Linux (idle) | $7.59 | $8.76 | $8.32 | [EC2 Pricing](https://aws.amazon.com/ec2/pricing/on-demand/) ($0.0104 / $0.0120 / $0.0114 per hr) |
| EC2 Instance | t3.small Linux (idle) | $15.18 | $17.52 | $16.64 | [EC2 Pricing](https://aws.amazon.com/ec2/pricing/on-demand/) ($0.0208 / $0.0240 / $0.0228 per hr) |
| RDS Instance | db.t4g.micro Single-AZ | $11.68 | $13.14 | $12.41 | [RDS Pricing](https://aws.amazon.com/rds/pricing/) ($0.016 / $0.018 / $0.017 per hr) |
| RDS Instance | db.t3.micro Single-AZ | $12.41 | $13.87 | $13.14 | [RDS Pricing](https://aws.amazon.com/rds/pricing/) ($0.017 / $0.019 / $0.018 per hr) |
| SageMaker Notebook | ml.t3.medium (idle) | $36.50 | $42.34 | $36.50 | [SageMaker Pricing](https://aws.amazon.com/sagemaker/pricing/) ($0.050 / $0.058 per hr) |

### Notes on Idle Resource Costs
- **NAT Gateway**: Even with 0 bytes transferred, AWS bills for every hour the gateway exists ($32.85/month in `us-east-1`). Deleting the NAT gateway leaves its allocated Elastic IP behind; the Elastic IP detector flags that on subsequent runs.
- **Elastic IP**: Since February 2024, all public IPv4 addresses cost $0.005 per hour ($3.65/month), whether attached or unattached.
- **EBS Volumes**: Unattached volumes keep billing for provisioned storage until snapshotted and deleted.
- **RDS Stopped State Limit**: AWS restarts stopped RDS database instances automatically after 7 consecutive days. Stopping RDS is therefore a temporary mitigation, not a permanent deletion.

---

## 2. Running Cost of Bill Shock Guard Itself

Bill Shock Guard is designed to run within the AWS Free Tier allowances so students do not pay to protect their accounts.

Below are the explicit formulas, inputs, and rates used to calculate monthly infrastructure costs.

### Stated Operational Assumptions
- **Schedule**: EventBridge triggers the Lambda once every 6 hours (`rate(6 hours)`).
  - Monthly scan count: 730 hours / 6 hours = 121.67 -> **122 scans per month**.
- **Lambda Configuration**:
  - Architecture: arm64 (AWS Graviton2).
  - Memory: 512 MB (0.50 GB).
  - Single-region scan duration: ~10 seconds.
  - Multi-region scan duration (17 enabled regions): ~30 seconds.
- **State Store**: DynamoDB table with On-Demand capacity model (`PAY_PER_REQUEST`). Finding state consumes under 1 MB of storage across ~30 items.
- **Notifications**: At most 1 digest email sent via Amazon SNS per scan, only when new findings or state transitions occur. Typical monthly volume: 5 to 20 emails.
- **CloudWatch Metric Queries**: CloudWatch `GetMetricData` calls are made only for active candidate resources discovered during the run.

### Official AWS Service Rates and Free Tier Allowances

1. **AWS Lambda**:
   - Free Tier: 1,000,000 requests and 400,000 GB-seconds per month (Always Free).
   - Standard arm64 pricing: $0.20 per 1,000,000 requests; $0.0000133334 per GB-second.
2. **Amazon DynamoDB**:
   - Free Tier: 25 GB data storage free forever.
   - On-Demand pricing: $1.25 per million write request units; $0.25 per million read request units.
3. **Amazon SNS**:
   - Free Tier: 1,000 email notifications free per month (Always Free).
   - Standard pricing: $2.00 per 100,000 email notifications thereafter.
4. **Amazon CloudWatch GetMetricData**:
   - Free Tier: None. `GetMetricData` is billed from the first request.
   - Standard pricing: $0.01 per 1,000 metrics requested.
5. **Amazon CloudWatch Logs**:
   - Free Tier: 5 GB monthly data ingestion free forever.
   - Standard pricing: $0.50 per GB ingested thereafter.
6. **Amazon EventBridge**:
   - Scheduled rules on the default bus: $0.00 (no charge).

---

### Cost Computation by Scenario

#### Scenario A: Single-Region Deployment (e.g., student testing in us-east-1 or ap-south-1)

Assumed candidate resources in account: 2 EC2 instances (6 metrics), 1 NAT gateway (1 metric), 1 ALB (1 metric) = 8 metric queries per scan.

1. **CloudWatch GetMetricData**:
   - Calculation: 122 scans * 8 metrics = 976 metric requests/month.
   - Unit price: $0.01 / 1,000 metrics.
   - Monthly cost: (976 / 1,000) * $0.01 = **$0.0098** (~$0.01).
2. **AWS Lambda**:
   - Execution duration: 122 scans * 10 seconds = 1,220 seconds.
   - Compute consumption: 1,220 seconds * 0.50 GB = 610 GB-seconds/month.
   - Allowance check: 610 GB-seconds < 400,000 GB-seconds free tier limit.
   - Allowance check: 122 requests < 1,000,000 requests free tier limit.
   - Monthly cost: **$0.00** (Free Tier).
   - (Without free tier: (122 / 1,000,000 * $0.20) + (610 * $0.0000133334) = $0.00002 + $0.00813 = $0.00815 ~ $0.01).
3. **Amazon DynamoDB**:
   - Storage: < 1 MB (< 25 GB free tier limit).
   - Capacity model: On-Demand (`PAY_PER_REQUEST`). Total monthly requests < 2,000.
   - Monthly cost: **$0.00** (< $0.0001).
4. **Amazon SNS**:
   - Email notifications: 10 emails/month (< 1,000 free tier limit).
   - Monthly cost: **$0.00** (Free Tier).
5. **CloudWatch Logs**:
   - Log volume: 122 scans * 5 KB = 610 KB/month (< 5 GB free tier limit).
   - Monthly cost: **$0.00** (Free Tier).

**Scenario A Total Monthly Running Cost**:
- **With Free Tier**: **$0.01 / month** (under 1 cent).
- **Without Free Tier**: **$0.02 / month** ($0.0098 metric queries + $0.0081 Lambda + $0.0001 DynamoDB).

---

#### Scenario B: Multi-Region Deployment (All 17 default commercial AWS regions)

Assumed candidate resources across all 17 regions: 6 EC2 instances (18 metrics), 2 NAT gateways (2 metrics), 2 ALBs (2 metrics) = 22 metric queries per scan.

1. **CloudWatch GetMetricData**:
   - Calculation: 122 scans * 22 metrics = 2,684 metric requests/month.
   - Unit price: $0.01 / 1,000 metrics.
   - Monthly cost: (2,684 / 1,000) * $0.01 = **$0.0268** (~$0.03).
2. **AWS Lambda**:
   - Execution duration: 122 scans * 30 seconds = 3,660 seconds.
   - Compute consumption: 3,660 seconds * 0.50 GB = 1,830 GB-seconds/month.
   - Allowance check: 1,830 GB-seconds is 0.46% of the 400,000 GB-seconds monthly free allowance.
   - Monthly cost: **$0.00** (Free Tier).
   - (Without free tier: (122 / 1,000,000 * $0.20) + (1,830 * $0.0000133334) = $0.00002 + $0.0244 = $0.0244 ~ $0.02).
3. **Amazon DynamoDB**:
   - Storage: < 2 MB (< 25 GB free tier limit).
   - Capacity model: On-Demand (`PAY_PER_REQUEST`). Total monthly requests < 5,000.
   - Monthly cost: **$0.00** (< $0.0002).
4. **Amazon SNS**:
   - Email notifications: ~20 emails/month (< 1,000 free tier limit).
   - Monthly cost: **$0.00** (Free Tier).
5. **CloudWatch Logs**:
   - Log volume: 122 scans * 15 KB = 1.83 MB/month (< 5 GB free tier limit).
   - Monthly cost: **$0.00** (Free Tier).

**Scenario B Total Monthly Running Cost**:
- **With Free Tier**: **$0.03 / month** (about 3 cents).
- **Without Free Tier**: **$0.05 / month** ($0.0268 metric queries + $0.0244 Lambda + $0.0002 DynamoDB).

---

## 3. Cost-to-Savings Summary

Running Bill Shock Guard continuously costs between **$0.01 and $0.03 per month** under normal free tier usage.

Catching even one forgotten resource saves:
- One idle NAT Gateway: **$32.85 to $40.88 / month**
- One unattached Elastic IP: **$3.65 / month**
- One idle Application Load Balancer: **$16.43 to $17.45 / month**
- One 50 GB unattached EBS volume: **$4.00 to $4.56 / month**
- One idle t3.micro EC2 instance: **$7.59 to $8.76 / month**

Total monthly savings from catching a single forgotten test stack: **$64.52 to $75.30 per month**, against a tool running cost of 3 cents.

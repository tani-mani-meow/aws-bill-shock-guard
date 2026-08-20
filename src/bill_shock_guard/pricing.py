"""AWS pricing lookup and monthly cost estimations.

All pricing figures reflect on-demand rates in USD.
Table verified as of PRICE_TABLE_DATE against official AWS documentation.
"""

from dataclasses import dataclass
from typing import Any

from bill_shock_guard.models import Confidence, ResourceType

HOURS_PER_MONTH: int = 730
PRICE_TABLE_DATE: str = "2026-11-12"
FALLBACK_REGION: str = "us-east-1"


@dataclass(frozen=True)
class PriceEntry:
    """A verified or estimated price entry for an AWS resource."""

    rate: float
    unit: str  # e.g., "USD/hour", "USD/GB-month"
    verified: bool
    last_verified: str
    source_url: str


# Regional pricing table for standard resource types.
# Key: (region, ResourceType)
PRICING_TABLE: dict[tuple[str, ResourceType], PriceEntry] = {
    # --- US East (N. Virginia) us-east-1 ---
    (
        "us-east-1",
        ResourceType.NAT_GATEWAY,
    ): PriceEntry(
        rate=0.045,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "us-east-1",
        ResourceType.ELASTIC_IP,
    ): PriceEntry(
        rate=0.005,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "us-east-1",
        ResourceType.LOAD_BALANCER,
    ): PriceEntry(
        rate=0.0225,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/elasticloadbalancing/pricing/",
    ),
    (
        "us-east-1",
        ResourceType.EBS_VOLUME,
    ): PriceEntry(
        rate=0.08,
        unit="USD/GB-month",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ebs/pricing/",
    ),
    # --- Asia Pacific (Mumbai) ap-south-1 ---
    (
        "ap-south-1",
        ResourceType.NAT_GATEWAY,
    ): PriceEntry(
        rate=0.056,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "ap-south-1",
        ResourceType.ELASTIC_IP,
    ): PriceEntry(
        rate=0.005,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "ap-south-1",
        ResourceType.LOAD_BALANCER,
    ): PriceEntry(
        rate=0.0239,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/elasticloadbalancing/pricing/",
    ),
    (
        "ap-south-1",
        ResourceType.EBS_VOLUME,
    ): PriceEntry(
        rate=0.0912,
        unit="USD/GB-month",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ebs/pricing/",
    ),
    # --- Europe (Ireland) eu-west-1 ---
    (
        "eu-west-1",
        ResourceType.NAT_GATEWAY,
    ): PriceEntry(
        rate=0.048,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "eu-west-1",
        ResourceType.ELASTIC_IP,
    ): PriceEntry(
        rate=0.005,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/vpc/pricing/",
    ),
    (
        "eu-west-1",
        ResourceType.LOAD_BALANCER,
    ): PriceEntry(
        rate=0.0225,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/elasticloadbalancing/pricing/",
    ),
    (
        "eu-west-1",
        ResourceType.EBS_VOLUME,
    ): PriceEntry(
        rate=0.088,
        unit="USD/GB-month",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ebs/pricing/",
    ),
}

# Regional EC2 On-Demand Linux pricing table.
# Key: (region, instance_type.lower())
EC2_PRICING_TABLE: dict[tuple[str, str], PriceEntry] = {
    # us-east-1
    ("us-east-1", "t4g.nano"): PriceEntry(
        rate=0.0042,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t4g.micro"): PriceEntry(
        rate=0.0084,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t4g.small"): PriceEntry(
        rate=0.0168,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t4g.medium"): PriceEntry(
        rate=0.0336,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t3.nano"): PriceEntry(
        rate=0.0052,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t3.micro"): PriceEntry(
        rate=0.0104,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t3.small"): PriceEntry(
        rate=0.0208,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t3.medium"): PriceEntry(
        rate=0.0416,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t3.large"): PriceEntry(
        rate=0.0832,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t2.nano"): PriceEntry(
        rate=0.0058,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t2.micro"): PriceEntry(
        rate=0.0116,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t2.small"): PriceEntry(
        rate=0.0230,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "t2.medium"): PriceEntry(
        rate=0.0464,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "m5.large"): PriceEntry(
        rate=0.0960,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("us-east-1", "c5.large"): PriceEntry(
        rate=0.0850,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    # ap-south-1
    ("ap-south-1", "t4g.nano"): PriceEntry(
        rate=0.0048,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("ap-south-1", "t4g.micro"): PriceEntry(
        rate=0.0096,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("ap-south-1", "t3.micro"): PriceEntry(
        rate=0.0120,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("ap-south-1", "t3.small"): PriceEntry(
        rate=0.0240,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("ap-south-1", "t3.medium"): PriceEntry(
        rate=0.0480,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    # eu-west-1
    ("eu-west-1", "t4g.nano"): PriceEntry(
        rate=0.0046,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("eu-west-1", "t3.micro"): PriceEntry(
        rate=0.0114,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
    ("eu-west-1", "t3.small"): PriceEntry(
        rate=0.0228,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/ec2/pricing/on-demand/",
    ),
}

# Regional RDS On-Demand Single-AZ PostgreSQL/MySQL pricing table.
# Key: (region, instance_type.lower())
RDS_PRICING_TABLE: dict[tuple[str, str], PriceEntry] = {
    # us-east-1
    ("us-east-1", "db.t4g.micro"): PriceEntry(
        rate=0.016,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
    ("us-east-1", "db.t3.micro"): PriceEntry(
        rate=0.017,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
    # ap-south-1
    ("ap-south-1", "db.t4g.micro"): PriceEntry(
        rate=0.018,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
    ("ap-south-1", "db.t3.micro"): PriceEntry(
        rate=0.019,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
    # eu-west-1
    ("eu-west-1", "db.t4g.micro"): PriceEntry(
        rate=0.017,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
    ("eu-west-1", "db.t3.micro"): PriceEntry(
        rate=0.018,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/rds/pricing/",
    ),
}

# Regional SageMaker Notebook instance pricing table.
# Key: (region, instance_type.lower())
SAGEMAKER_PRICING_TABLE: dict[tuple[str, str], PriceEntry] = {
    # us-east-1
    ("us-east-1", "ml.t3.medium"): PriceEntry(
        rate=0.050,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/sagemaker/pricing/",
    ),
    ("us-east-1", "ml.t2.medium"): PriceEntry(
        rate=0.050,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/sagemaker/pricing/",
    ),
    # ap-south-1
    ("ap-south-1", "ml.t3.medium"): PriceEntry(
        rate=0.058,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/sagemaker/pricing/",
    ),
    # eu-west-1
    ("eu-west-1", "ml.t3.medium"): PriceEntry(
        rate=0.050,
        unit="USD/hour",
        verified=True,
        last_verified="2026-11-12",
        source_url="https://aws.amazon.com/sagemaker/pricing/",
    ),
}


def get_price_entry(
    resource_type: ResourceType | str,
    region: str = FALLBACK_REGION,
    **attrs: Any,
) -> PriceEntry | None:
    """Retrieve raw PriceEntry for a resource, falling back to us-east-1 if needed."""
    resolved_rt: ResourceType
    if isinstance(resource_type, ResourceType):
        resolved_rt = resource_type
    elif isinstance(resource_type, str):
        try:
            resolved_rt = ResourceType(resource_type)
        except ValueError:
            return None
    else:
        return None

    norm_region = (region or FALLBACK_REGION).strip().lower()

    if resolved_rt == ResourceType.EC2_INSTANCE:
        itype = attrs.get("instance_type") or attrs.get("type")
        if not itype or not isinstance(itype, str):
            return None
        norm_type = itype.strip().lower()
        entry = EC2_PRICING_TABLE.get((norm_region, norm_type))
        if entry is None and norm_region != FALLBACK_REGION:
            entry = EC2_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        return entry

    if resolved_rt == ResourceType.RDS_INSTANCE:
        itype = attrs.get("instance_type") or attrs.get("db_instance_class") or attrs.get("type")
        if not itype or not isinstance(itype, str):
            return None
        norm_type = itype.strip().lower()
        entry = RDS_PRICING_TABLE.get((norm_region, norm_type))
        if entry is None and norm_region != FALLBACK_REGION:
            entry = RDS_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        return entry

    if resolved_rt == ResourceType.SAGEMAKER_NOTEBOOK:
        itype = (
            attrs.get("instance_type") or attrs.get("notebook_instance_type") or attrs.get("type")
        )
        if not itype or not isinstance(itype, str):
            return None
        norm_type = itype.strip().lower()
        entry = SAGEMAKER_PRICING_TABLE.get((norm_region, norm_type))
        if entry is None and norm_region != FALLBACK_REGION:
            entry = SAGEMAKER_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        return entry

    # General standard resource types (NAT, EIP, ALB, EBS)
    entry = PRICING_TABLE.get((norm_region, resolved_rt))
    if entry is None and norm_region != FALLBACK_REGION:
        entry = PRICING_TABLE.get((FALLBACK_REGION, resolved_rt))
    return entry


def monthly_cost(
    resource_type: ResourceType,
    region: str,
    **attrs: Any,
) -> tuple[float | None, Confidence]:
    """Calculate approximate monthly cost in USD for a resource.

    Returns:
        (est_monthly_cost_usd, confidence)
    """
    resolved_rt: ResourceType
    if isinstance(resource_type, ResourceType):
        resolved_rt = resource_type
    elif isinstance(resource_type, str):
        try:
            resolved_rt = ResourceType(resource_type)
        except ValueError:
            return None, "unknown"
    else:
        return None, "unknown"

    norm_region = (region or FALLBACK_REGION).strip().lower()

    # --- EC2 Instance ---
    if resolved_rt == ResourceType.EC2_INSTANCE:
        raw_type = attrs.get("instance_type") or attrs.get("type")
        if not raw_type or not isinstance(raw_type, str):
            # Without instance_type, EC2 cost cannot be estimated honestly
            return None, "unknown"
        norm_type = raw_type.strip().lower()
        ec2_entry = EC2_PRICING_TABLE.get((norm_region, norm_type))
        if ec2_entry is None and norm_region != FALLBACK_REGION:
            ec2_entry = EC2_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        if ec2_entry is None:
            return None, "unknown"
        cost = round(ec2_entry.rate * HOURS_PER_MONTH, 2)
        return cost, "estimate"

    # --- RDS Instance ---
    if resolved_rt == ResourceType.RDS_INSTANCE:
        raw_type = attrs.get("instance_type") or attrs.get("db_instance_class") or attrs.get("type")
        if not raw_type or not isinstance(raw_type, str):
            return None, "unknown"
        norm_type = raw_type.strip().lower()
        rds_entry = RDS_PRICING_TABLE.get((norm_region, norm_type))
        if rds_entry is None and norm_region != FALLBACK_REGION:
            rds_entry = RDS_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        if rds_entry is None:
            return None, "unknown"
        cost = round(rds_entry.rate * HOURS_PER_MONTH, 2)
        return cost, "estimate"

    # --- SageMaker Notebook ---
    if resolved_rt == ResourceType.SAGEMAKER_NOTEBOOK:
        raw_type = (
            attrs.get("instance_type") or attrs.get("notebook_instance_type") or attrs.get("type")
        )
        if not raw_type or not isinstance(raw_type, str):
            return None, "unknown"
        norm_type = raw_type.strip().lower()
        sm_entry = SAGEMAKER_PRICING_TABLE.get((norm_region, norm_type))
        if sm_entry is None and norm_region != FALLBACK_REGION:
            sm_entry = SAGEMAKER_PRICING_TABLE.get((FALLBACK_REGION, norm_type))
        if sm_entry is None:
            return None, "unknown"
        cost = round(sm_entry.rate * HOURS_PER_MONTH, 2)
        return cost, "estimate"

    # --- EBS Volume ---
    if resolved_rt == ResourceType.EBS_VOLUME:
        ebs_entry = PRICING_TABLE.get((norm_region, ResourceType.EBS_VOLUME))
        if ebs_entry is None and norm_region != FALLBACK_REGION:
            ebs_entry = PRICING_TABLE.get((FALLBACK_REGION, ResourceType.EBS_VOLUME))
        if ebs_entry is None:
            return None, "unknown"

        size = (
            attrs.get("size_gb")
            if attrs.get("size_gb") is not None
            else attrs.get("size_gib")
            if attrs.get("size_gib") is not None
            else attrs.get("size")
            if attrs.get("size") is not None
            else attrs.get("volume_size")
        )
        if size is None:
            # Baseline unit cost for 1 GB-month provisioned storage
            qty = 1.0
        else:
            try:
                qty = float(size)
                if qty < 0:
                    return None, "unknown"
            except (ValueError, TypeError):
                return None, "unknown"
        cost = round(qty * ebs_entry.rate, 2)
        return cost, "estimate"

    # --- Standard Hourly Resources: NAT Gateway, Elastic IP, Load Balancer ---
    if resolved_rt in (
        ResourceType.NAT_GATEWAY,
        ResourceType.ELASTIC_IP,
        ResourceType.LOAD_BALANCER,
    ):
        entry = PRICING_TABLE.get((norm_region, resolved_rt))
        if entry is None and norm_region != FALLBACK_REGION:
            entry = PRICING_TABLE.get((FALLBACK_REGION, resolved_rt))
        if entry is None:
            return None, "unknown"

        raw_count = attrs.get("count", 1)
        try:
            count = float(raw_count)
            if count < 0:
                return None, "unknown"
        except (ValueError, TypeError):
            return None, "unknown"

        cost = round(count * entry.rate * HOURS_PER_MONTH, 2)
        return cost, "estimate"

    # Any unhandled resource type with no data
    return None, "unknown"

"""Unit tests for AWS pricing lookup and monthly cost calculations."""

from typing import Any

from bill_shock_guard.models import ResourceType
from bill_shock_guard.pricing import (
    EC2_PRICING_TABLE,
    FALLBACK_REGION,
    HOURS_PER_MONTH,
    PRICE_TABLE_DATE,
    PRICING_TABLE,
    RDS_PRICING_TABLE,
    SAGEMAKER_PRICING_TABLE,
    PriceEntry,
    get_price_entry,
    monthly_cost,
)


def test_pricing_constants() -> None:
    """Verify frozen constants: 730 hours per month and verified date."""
    assert HOURS_PER_MONTH == 730
    assert PRICE_TABLE_DATE == "2026-11-12"
    assert FALLBACK_REGION == "us-east-1"


def test_nat_gateway_monthly_cost() -> None:
    """Verify NAT gateway monthly cost calculations and regional rates."""
    # us-east-1: $0.045/hr * 730 hrs = $32.85
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "us-east-1")
    assert cost == 32.85
    assert conf == "estimate"

    # ap-south-1: $0.056/hr * 730 hrs = $40.88
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "ap-south-1")
    assert cost == 40.88
    assert conf == "estimate"

    # eu-west-1: $0.048/hr * 730 hrs = $35.04
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "eu-west-1")
    assert cost == 35.04
    assert conf == "estimate"

    # Multiple NAT gateways (count=2)
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "us-east-1", count=2)
    assert cost == 65.70
    assert conf == "estimate"


def test_elastic_ip_monthly_cost() -> None:
    """Verify public IPv4 unattached Elastic IP monthly cost ($0.005/hr * 730 = $3.65)."""
    cost, conf = monthly_cost(ResourceType.ELASTIC_IP, "us-east-1")
    assert cost == 3.65
    assert conf == "estimate"

    # ap-south-1 flat global IPv4 pricing
    cost, conf = monthly_cost(ResourceType.ELASTIC_IP, "ap-south-1")
    assert cost == 3.65
    assert conf == "estimate"

    # Multiple unattached EIPs
    cost, conf = monthly_cost(ResourceType.ELASTIC_IP, "us-east-1", count=3)
    assert cost == 10.95
    assert conf == "estimate"


def test_load_balancer_monthly_cost() -> None:
    """Verify Application Load Balancer monthly cost ($0.0225/hr * 730 = $16.43 in us-east-1)."""
    # us-east-1: 0.0225 * 730 = 16.425 -> 16.43
    cost, conf = monthly_cost(ResourceType.LOAD_BALANCER, "us-east-1")
    assert cost == 16.43
    assert conf == "estimate"

    # ap-south-1: 0.0239 * 730 = 17.447 -> 17.45
    cost, conf = monthly_cost(ResourceType.LOAD_BALANCER, "ap-south-1")
    assert cost == 17.45
    assert conf == "estimate"

    # eu-west-1: 0.0225 * 730 = 16.43
    cost, conf = monthly_cost(ResourceType.LOAD_BALANCER, "eu-west-1")
    assert cost == 16.43
    assert conf == "estimate"

    # Passing lb_type should work gracefully
    cost, conf = monthly_cost(ResourceType.LOAD_BALANCER, "us-east-1", lb_type="application")
    assert cost == 16.43
    assert conf == "estimate"


def test_ebs_volume_monthly_cost() -> None:
    """Verify EBS gp3 volume monthly cost by provisioned gigabytes."""
    # Baseline 1 GB unit rate in us-east-1 ($0.08/GB-month)
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1")
    assert cost == 0.08
    assert conf == "estimate"

    # 100 GB in us-east-1 = 100 * 0.08 = 8.00
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gb=100)
    assert cost == 8.00
    assert conf == "estimate"

    # 20 GB in us-east-1 = 20 * 0.08 = 1.60
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gb=20)
    assert cost == 1.60
    assert conf == "estimate"

    # 8 GB root volume in us-east-1 = 8 * 0.08 = 0.64
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gb=8)
    assert cost == 0.64
    assert conf == "estimate"

    # 100 GB in ap-south-1 = 100 * 0.0912 = 9.12
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "ap-south-1", size_gb=100)
    assert cost == 9.12
    assert conf == "estimate"

    # 100 GB in eu-west-1 = 100 * 0.088 = 8.80
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "eu-west-1", size_gb=100)
    assert cost == 8.80
    assert conf == "estimate"

    # Attribute aliases: size_gib, size, volume_size
    assert monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gib=50)[0] == 4.00
    assert monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size=50)[0] == 4.00
    assert monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", volume_size=50)[0] == 4.00


def test_ec2_instance_monthly_cost() -> None:
    """Verify EC2 On-Demand Linux instance monthly cost calculations."""
    # t3.micro in us-east-1: 0.0104 * 730 = 7.592 -> 7.59
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", instance_type="t3.micro")
    assert cost == 7.59
    assert conf == "estimate"

    # t4g.nano in us-east-1: 0.0042 * 730 = 3.066 -> 3.07
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", instance_type="t4g.nano")
    assert cost == 3.07
    assert conf == "estimate"

    # t3.small in us-east-1: 0.0208 * 730 = 15.184 -> 15.18
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", instance_type="t3.small")
    assert cost == 15.18
    assert conf == "estimate"

    # t3.micro in ap-south-1: 0.0120 * 730 = 8.76
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "ap-south-1", instance_type="t3.micro")
    assert cost == 8.76
    assert conf == "estimate"

    # Case insensitivity and whitespace stripping
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", instance_type=" T3.MICRO ")
    assert cost == 7.59
    assert conf == "estimate"

    # type alias kwarg
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", type="t3.micro")
    assert cost == 7.59
    assert conf == "estimate"

    # Missing instance_type returns (None, 'unknown') (cannot make up a number)
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1")
    assert cost is None
    assert conf == "unknown"

    # Non-string instance_type
    cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, "us-east-1", instance_type=123)
    assert cost is None
    assert conf == "unknown"

    # Unknown instance type returns (None, 'unknown')
    cost, conf = monthly_cost(
        ResourceType.EC2_INSTANCE, "us-east-1", instance_type="nonexistent.xlarge"
    )
    assert cost is None
    assert conf == "unknown"


def test_rds_instance_monthly_cost() -> None:
    """Verify RDS Single-AZ database instance monthly cost."""
    # db.t4g.micro in us-east-1: 0.016 * 730 = 11.68
    cost, conf = monthly_cost(ResourceType.RDS_INSTANCE, "us-east-1", instance_type="db.t4g.micro")
    assert cost == 11.68
    assert conf == "estimate"

    # db.t3.micro in us-east-1: 0.017 * 730 = 12.41
    cost, conf = monthly_cost(ResourceType.RDS_INSTANCE, "us-east-1", instance_type="db.t3.micro")
    assert cost == 12.41
    assert conf == "estimate"

    # db.t3.micro fallback from unverified region (e.g. us-west-2) to us-east-1
    cost, conf = monthly_cost(ResourceType.RDS_INSTANCE, "us-west-2", instance_type="db.t3.micro")
    assert cost == 12.41
    assert conf == "estimate"

    # Missing instance_type
    cost, conf = monthly_cost(ResourceType.RDS_INSTANCE, "us-east-1")
    assert cost is None
    assert conf == "unknown"

    # Non-string instance_type
    cost, conf = monthly_cost(ResourceType.RDS_INSTANCE, "us-east-1", instance_type=123)
    assert cost is None
    assert conf == "unknown"

    # Unknown instance_type
    cost, conf = monthly_cost(
        ResourceType.RDS_INSTANCE, "us-east-1", instance_type="db.unknown.class"
    )
    assert cost is None
    assert conf == "unknown"


def test_sagemaker_notebook_monthly_cost() -> None:
    """Verify SageMaker Notebook instance monthly cost."""
    # ml.t3.medium in us-east-1: 0.050 * 730 = 36.50
    cost, conf = monthly_cost(
        ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1", instance_type="ml.t3.medium"
    )
    assert cost == 36.50
    assert conf == "estimate"

    # ml.t3.medium in ap-south-1: 0.058 * 730 = 42.34
    cost, conf = monthly_cost(
        ResourceType.SAGEMAKER_NOTEBOOK, "ap-south-1", instance_type="ml.t3.medium"
    )
    assert cost == 42.34
    assert conf == "estimate"

    # ml.t3.medium fallback from unverified region (e.g. us-west-2) to us-east-1
    cost, conf = monthly_cost(
        ResourceType.SAGEMAKER_NOTEBOOK, "us-west-2", instance_type="ml.t3.medium"
    )
    assert cost == 36.50
    assert conf == "estimate"

    # Missing instance_type
    cost, conf = monthly_cost(ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1")
    assert cost is None
    assert conf == "unknown"

    # Non-string instance_type
    cost, conf = monthly_cost(ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1", instance_type=123)
    assert cost is None
    assert conf == "unknown"

    # Unknown instance_type
    cost, conf = monthly_cost(
        ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1", instance_type="ml.unknown"
    )
    assert cost is None
    assert conf == "unknown"


def test_region_fallback_to_us_east_1() -> None:
    """Verify regions without explicit verified entries fall back to us-east-1."""
    unverified_regions = ["us-west-2", "sa-east-1", "ap-southeast-1", "ca-central-1"]

    for region in unverified_regions:
        # NAT Gateway fallback to us-east-1 ($32.85)
        cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, region)
        assert cost == 32.85
        assert conf == "estimate"

        # Elastic IP fallback to us-east-1 ($3.65)
        cost, conf = monthly_cost(ResourceType.ELASTIC_IP, region)
        assert cost == 3.65
        assert conf == "estimate"

        # ALB fallback to us-east-1 ($16.43)
        cost, conf = monthly_cost(ResourceType.LOAD_BALANCER, region)
        assert cost == 16.43
        assert conf == "estimate"

        # EBS 100 GB fallback to us-east-1 ($8.00)
        cost, conf = monthly_cost(ResourceType.EBS_VOLUME, region, size_gb=100)
        assert cost == 8.00
        assert conf == "estimate"

        # EC2 t3.micro fallback to us-east-1 ($7.59)
        cost, conf = monthly_cost(ResourceType.EC2_INSTANCE, region, instance_type="t3.micro")
        assert cost == 7.59
        assert conf == "estimate"


def test_string_resource_type_coercion() -> None:
    """Verify passing string values instead of ResourceType enum is handled cleanly."""
    cost, conf = monthly_cost("nat_gateway", "us-east-1")  # type: ignore[arg-type]
    assert cost == 32.85
    assert conf == "estimate"

    cost, conf = monthly_cost("elastic_ip", "us-east-1")  # type: ignore[arg-type]
    assert cost == 3.65
    assert conf == "estimate"

    # Nonexistent string resource type
    cost, conf = monthly_cost("nonexistent_resource", "us-east-1")  # type: ignore[arg-type]
    assert cost is None
    assert conf == "unknown"


def test_invalid_attributes_handling() -> None:
    """Verify invalid numeric inputs return (None, 'unknown') without raising exceptions."""
    # Negative count
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "us-east-1", count=-1)
    assert cost is None
    assert conf == "unknown"

    # Non-numeric count
    cost, conf = monthly_cost(ResourceType.NAT_GATEWAY, "us-east-1", count="abc")
    assert cost is None
    assert conf == "unknown"

    # Negative volume size
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gb=-10)
    assert cost is None
    assert conf == "unknown"

    # Non-numeric volume size
    cost, conf = monthly_cost(ResourceType.EBS_VOLUME, "us-east-1", size_gb="bad_val")
    assert cost is None
    assert conf == "unknown"

    # Non-ResourceType, non-str object
    cost, conf = monthly_cost(12345, "us-east-1")  # type: ignore[arg-type]
    assert cost is None
    assert conf == "unknown"


def test_pricing_table_entry_integrity() -> None:
    """Verify all entries in PRICING_TABLE and sub-tables have verified URLs, dates, and rates."""
    all_tables: list[dict[Any, PriceEntry]] = [
        PRICING_TABLE,
        EC2_PRICING_TABLE,
        RDS_PRICING_TABLE,
        SAGEMAKER_PRICING_TABLE,
    ]

    for table in all_tables:
        for key, entry in table.items():
            assert entry.rate > 0, f"Rate must be positive for {key}: {entry}"
            assert entry.unit in ("USD/hour", "USD/GB-month")
            assert entry.verified is True
            assert entry.last_verified == PRICE_TABLE_DATE
            assert entry.source_url.startswith("https://aws.amazon.com/")


def test_get_price_entry_helper() -> None:
    """Verify get_price_entry returns the underlying PriceEntry with fallback."""
    # Direct lookup
    entry = get_price_entry(ResourceType.NAT_GATEWAY, "us-east-1")
    assert entry is not None
    assert entry.rate == 0.045
    assert entry.source_url == "https://aws.amazon.com/vpc/pricing/"

    # Fallback lookup
    entry = get_price_entry(ResourceType.NAT_GATEWAY, "us-west-2")
    assert entry is not None
    assert entry.rate == 0.045

    # EC2 instance entry lookup
    entry = get_price_entry(ResourceType.EC2_INSTANCE, "us-east-1", instance_type="t3.micro")
    assert entry is not None
    assert entry.rate == 0.0104

    # EC2 instance entry fallback
    entry = get_price_entry(ResourceType.EC2_INSTANCE, "us-west-2", instance_type="t3.micro")
    assert entry is not None
    assert entry.rate == 0.0104

    # EC2 without instance_type
    assert get_price_entry(ResourceType.EC2_INSTANCE, "us-east-1") is None
    assert get_price_entry(ResourceType.EC2_INSTANCE, "us-east-1", instance_type=123) is None

    # RDS entry lookup and fallback
    entry = get_price_entry(ResourceType.RDS_INSTANCE, "us-east-1", instance_type="db.t3.micro")
    assert entry is not None
    assert entry.rate == 0.017

    entry = get_price_entry(ResourceType.RDS_INSTANCE, "us-west-2", instance_type="db.t3.micro")
    assert entry is not None
    assert entry.rate == 0.017

    assert get_price_entry(ResourceType.RDS_INSTANCE, "us-east-1") is None
    assert get_price_entry(ResourceType.RDS_INSTANCE, "us-east-1", instance_type=123) is None

    # SageMaker entry lookup and fallback
    entry = get_price_entry(
        ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1", instance_type="ml.t3.medium"
    )
    assert entry is not None
    assert entry.rate == 0.050

    entry = get_price_entry(
        ResourceType.SAGEMAKER_NOTEBOOK, "us-west-2", instance_type="ml.t3.medium"
    )
    assert entry is not None
    assert entry.rate == 0.050

    assert get_price_entry(ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1") is None
    assert get_price_entry(ResourceType.SAGEMAKER_NOTEBOOK, "us-east-1", instance_type=123) is None

    # String lookup
    entry = get_price_entry("nat_gateway", "us-east-1")
    assert entry is not None
    assert entry.rate == 0.045

    # Nonexistent resource returns None
    assert get_price_entry("nonexistent", "us-east-1") is None
    assert get_price_entry(123, "us-east-1") is None  # type: ignore[arg-type]

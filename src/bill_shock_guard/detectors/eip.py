"""Elastic IP detector, recheck, and release action."""

from datetime import datetime, timezone
from typing import Any, Mapping

from botocore.exceptions import ClientError

from bill_shock_guard.aws import mutation_outcome_unknown, paginate
from bill_shock_guard.config import Config
from bill_shock_guard.interfaces import Action, Detector, ScanContext
from bill_shock_guard.models import (
    ActionKind,
    ActionResult,
    Finding,
    RecheckResult,
    ResourceType,
)
from bill_shock_guard.pricing import monthly_cost
from bill_shock_guard.protection import is_protected


def is_eip_unassociated(address: Mapping[str, Any]) -> bool:
    """Return True if the Elastic IP address has no association, instance, or ENI attached."""
    has_assoc = bool(address.get("AssociationId"))
    has_instance = bool(address.get("InstanceId"))
    has_eni = bool(address.get("NetworkInterfaceId"))
    return not (has_assoc or has_instance or has_eni)


def is_eip_idle(
    address: Mapping[str, Any],
    first_seen: datetime | None = None,
    now: datetime | None = None,
    min_age_hours: int = 0,
) -> bool:
    """Pure decision function evaluating whether an Elastic IP is unassociated.

    If first_seen is provided, also checks if older than min_age_hours.
    """
    if not is_eip_unassociated(address):
        return False

    if first_seen is not None and now is not None and min_age_hours > 0:
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        age_seconds = (now - first_seen).total_seconds()
        return age_seconds >= min_age_hours * 3600

    return True


def check_eip_protection(
    resource_id: str,
    tags: Mapping[str, str],
    public_ip: str | None,
    config: Config,
    now: datetime,
) -> tuple[bool, str | None]:
    """Pure function checking if an Elastic IP is protected or ignored."""
    prot, reason = is_protected(tags, resource_id, config, now)
    if prot:
        return True, reason

    if public_ip and public_ip in config.ignore_resource_ids:
        return True, f"Resource public IP {public_ip} is in ignore_resource_ids"

    return False, None


class EIPDetector:
    """Detector for unassociated Elastic IP addresses."""

    resource_type = ResourceType.ELASTIC_IP

    def detect(self, ctx: ScanContext, region: str) -> list[Finding]:
        """Scan Elastic IPs in region and flag unassociated addresses."""
        ec2 = ctx.client("ec2", region)
        findings: list[Finding] = []
        now = ctx.clock.now()

        try:
            for addr in paginate(ec2, "describe_addresses", "Addresses"):
                if not is_eip_unassociated(addr):
                    continue

                alloc_id = addr.get("AllocationId") or addr.get("PublicIp", "")
                public_ip = addr.get("PublicIp", "")
                raw_tags = addr.get("Tags", [])
                tags = {t["Key"]: t.get("Value", "") for t in raw_tags if "Key" in t}

                is_prot, prot_reason = check_eip_protection(
                    alloc_id, tags, public_ip, ctx.config, now
                )

                cost, confidence = monthly_cost(ResourceType.ELASTIC_IP, region)

                finding = Finding(
                    resource_type=ResourceType.ELASTIC_IP,
                    resource_id=alloc_id,
                    region=region,
                    reason=f"Elastic IP {public_ip} ({alloc_id}) is unassociated",
                    evidence={
                        "allocation_id": addr.get("AllocationId"),
                        "public_ip": public_ip,
                        "domain": addr.get("Domain", "vpc"),
                        "association_id": None,
                        "network_interface_id": None,
                        "instance_id": None,
                    },
                    est_monthly_cost_usd=cost,
                    cost_confidence=confidence,
                    proposed_action=ActionKind.EIP_RELEASE,
                    protected=is_prot,
                    protection_reason=prot_reason,
                    detected_at=now,
                )
                findings.append(finding)
        except Exception as e:
            ctx.report_scan_error(f"Elastic IP inventory: {e}")
            ctx.logger.error(
                f"Failed to describe Elastic IP addresses in {region}: {e}",
                extra={"region": region, "error": str(e)},
            )
            return findings

        return findings

    def recheck(self, ctx: ScanContext, finding: Finding) -> RecheckResult:
        """Re-verify single Elastic IP association state and tags before release."""
        ec2 = ctx.client("ec2", finding.region)
        now = ctx.clock.now()

        try:
            if finding.resource_id.startswith("eipalloc-"):
                resp = ec2.describe_addresses(AllocationIds=[finding.resource_id])
            else:
                resp = ec2.describe_addresses(PublicIps=[finding.resource_id])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidAllocationID.NotFound", "InvalidAddress.NotFound"):
                return RecheckResult(
                    still_idle=False,
                    protected=False,
                    reason=f"Elastic IP {finding.resource_id} not found (may have been released)",
                )
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe Elastic IP {finding.resource_id}: {e}",
            )
        except Exception as e:
            return RecheckResult(
                still_idle=None,
                protected=False,
                reason=f"Failed to describe Elastic IP {finding.resource_id}: {e}",
            )

        addresses = resp.get("Addresses", [])
        if not addresses:
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=f"Elastic IP {finding.resource_id} not found",
            )

        addr = addresses[0]
        if not is_eip_unassociated(addr):
            assoc_id = addr.get("AssociationId")
            inst_id = addr.get("InstanceId")
            eni_id = addr.get("NetworkInterfaceId")
            return RecheckResult(
                still_idle=False,
                protected=False,
                reason=(
                    f"Elastic IP {finding.resource_id} is now associated "
                    f"(AssociationId: {assoc_id}, InstanceId: {inst_id}, ENI: {eni_id})"
                ),
            )

        raw_tags = addr.get("Tags", [])
        tags = {t["Key"]: t.get("Value", "") for t in raw_tags if "Key" in t}
        is_prot, prot_reason = check_eip_protection(
            finding.resource_id, tags, addr.get("PublicIp"), ctx.config, now
        )

        if is_prot:
            return RecheckResult(
                still_idle=True,
                protected=True,
                reason=prot_reason or "Protected",
            )

        return RecheckResult(
            still_idle=True,
            protected=False,
            reason=f"Elastic IP {finding.resource_id} is still unassociated and unprotected",
        )


class EIPReleaseAction:
    """Action to release an unassociated Elastic IP address."""

    kind = ActionKind.EIP_RELEASE

    def apply(self, ctx: ScanContext, finding: Finding) -> ActionResult:
        """Release the address unless dry_run is active."""
        if ctx.config.dry_run:
            return ActionResult(
                ok=True,
                performed=False,
                detail=f"DRY RUN: would release Elastic IP {finding.resource_id}",
            )

        ec2 = ctx.client("ec2", finding.region)
        try:
            if finding.resource_id.startswith("eipalloc-"):
                ec2.release_address(AllocationId=finding.resource_id)
            else:
                ec2.release_address(PublicIp=finding.resource_id)
            return ActionResult(
                ok=True,
                performed=True,
                detail=f"Released Elastic IP {finding.resource_id}",
            )
        except Exception as e:
            return ActionResult(
                ok=False,
                performed=False,
                detail=f"Failed to release Elastic IP {finding.resource_id}: {e}",
                error=str(e),
                needs_reconciliation=mutation_outcome_unknown(e),
            )


DETECTORS: list[Detector] = [EIPDetector()]
ACTIONS: dict[ActionKind, Action] = {ActionKind.EIP_RELEASE: EIPReleaseAction()}

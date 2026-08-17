"""Core domain models, enums, and data types for Bill Shock Guard."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal, Mapping


class ResourceType(StrEnum):
    EC2_INSTANCE = "ec2_instance"
    ELASTIC_IP = "elastic_ip"
    NAT_GATEWAY = "nat_gateway"
    EBS_VOLUME = "ebs_volume"
    LOAD_BALANCER = "load_balancer"
    RDS_INSTANCE = "rds_instance"
    SAGEMAKER_NOTEBOOK = "sagemaker_notebook"


class ActionKind(StrEnum):
    EC2_STOP = "ec2_stop"
    EIP_RELEASE = "eip_release"
    NAT_DELETE = "nat_delete"
    EBS_DELETE_AFTER_SNAPSHOT = "ebs_delete_after_snapshot"
    ELB_DELETE = "elb_delete"
    RDS_STOP = "rds_stop"
    SM_NOTEBOOK_STOP = "sm_notebook_stop"


Confidence = Literal["estimate", "unknown"]


@dataclass(frozen=True)
class Finding:
    """A detected resource that may incur unnecessary charges."""

    resource_type: ResourceType
    resource_id: str
    region: str
    reason: str  # one line, human readable
    evidence: Mapping[str, object]  # raw numbers/attributes behind the decision
    est_monthly_cost_usd: float | None
    cost_confidence: Confidence
    proposed_action: ActionKind | None
    protected: bool
    protection_reason: str | None
    detected_at: datetime  # UTC aware

    @property
    def key(self) -> str:
        """Globally unique key for tracking across runs."""
        return f"{self.region}#{self.resource_type.value}#{self.resource_id}"


@dataclass(frozen=True)
class RecheckResult:
    """Live state re-verification right before taking any mutating action."""

    still_idle: bool | None  # None indicates unknown / API error
    protected: bool
    reason: str


@dataclass(frozen=True)
class ActionResult:
    """Outcome of attempting a mutating action on an AWS resource."""

    ok: bool
    performed: bool
    detail: str
    error: str | None = None
    needs_reconciliation: bool = False


class FindingStatus(StrEnum):
    DETECTED = "DETECTED"
    WARNED = "WARNED"
    EXEMPT = "EXEMPT"
    WOULD_ACT = "WOULD_ACT"
    ACTION_PENDING = "ACTION_PENDING"
    ACTED = "ACTED"
    FAILED = "FAILED"
    RESOLVED = "RESOLVED"


class Effect(StrEnum):
    NONE = "NONE"
    SEND_WARNING = "SEND_WARNING"
    ATTEMPT_ACTION = "ATTEMPT_ACTION"


@dataclass(frozen=True)
class Decision:
    """Pure state machine transition decision."""

    next_status: FindingStatus
    effect: Effect
    reason: str


@dataclass
class FindingState:
    """Persistent tracking state stored in DynamoDB or in-memory."""

    key: str
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    warned_at: datetime | None = None
    action_deadline: datetime | None = None
    attempts: int = 0
    last_error: str | None = None
    ttl: int | None = None  # epoch seconds (30 days after terminal state)
    version: int = 1  # conditional write concurrency counter
    metadata: dict[str, object] = field(default_factory=dict)

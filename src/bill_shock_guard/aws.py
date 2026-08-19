"""AWS client utilities, pagination helpers, and region discovery."""

from typing import Any, Callable, Iterator

import boto3
import botocore.config
import botocore.exceptions

DEFAULT_BOTO_CONFIG = botocore.config.Config(
    retries={"mode": "standard", "max_attempts": 5},
    connect_timeout=5,
    read_timeout=20,
)


def mutation_outcome_unknown(error: Exception) -> bool:
    """A transport error or server failure may occur after AWS accepted a request."""
    if not isinstance(error, botocore.exceptions.ClientError):
        return True
    status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    code = error.response.get("Error", {}).get("Code", "")
    return status >= 500 or code in {"RequestTimeout", "RequestTimeoutException"}


def get_boto_client(
    service_name: str,
    region_name: str | None = None,
    session: boto3.Session | None = None,
    config: botocore.config.Config | None = None,
) -> Any:
    """Create a configured boto3 client with standard timeouts and retry policy."""
    sess = session or boto3.Session()
    cfg = config or DEFAULT_BOTO_CONFIG
    return sess.client(service_name, region_name=region_name, config=cfg)


def get_enabled_regions(
    session: boto3.Session | None = None,
    target_regions: list[str] | None = None,
    *,
    strict: bool = False,
) -> list[str]:
    """Retrieve enabled regions for the account.

    If target_regions is provided and not ['*'], returns only matching enabled regions.
    In strict mode, report discovery failures to the caller.
    """
    client = get_boto_client("ec2", region_name="us-east-1", session=session)
    try:
        response = client.describe_regions(AllRegions=False)
        available = [r["RegionName"] for r in response.get("Regions", [])]
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.BotoCoreError,
    ):
        if strict:
            raise
        # Fallback to standard us-east-1 if describe_regions fails
        available = ["us-east-1"]

    if not target_regions or target_regions == ["*"]:
        return sorted(available)

    target_set = set(target_regions)
    return sorted([r for r in available if r in target_set])


def paginate(
    client: Any,
    operation_name: str,
    result_key: str,
    **kwargs: Any,
) -> Iterator[dict[str, Any]]:
    """Yield items from a paginated API response.

    Uses client.get_paginator if supported; otherwise falls back to a manual loop.
    """
    if client.can_paginate(operation_name):
        paginator = client.get_paginator(operation_name)
        for page in paginator.paginate(**kwargs):
            for item in page.get(result_key, []):
                yield item
    else:
        # Fallback manual call
        method: Callable[..., Any] = getattr(client, operation_name)
        resp = method(**kwargs)
        for item in resp.get(result_key, []):
            yield item

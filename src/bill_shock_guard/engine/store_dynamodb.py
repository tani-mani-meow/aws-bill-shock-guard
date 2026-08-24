"""DynamoDB StateStore implementation with conditional writes for optimistic concurrency."""

import json
from datetime import datetime, timezone
from typing import Any

import botocore.exceptions

from bill_shock_guard.aws import get_boto_client
from bill_shock_guard.engine.store_memory import OptimisticLockError
from bill_shock_guard.models import FindingState, FindingStatus


class DynamoDbStateStore:
    """DynamoDB implementation of StateStore using version attribute conditional writes."""

    def __init__(self, table_name: str, client: Any = None) -> None:
        self.table_name = table_name
        self._client = client if client is not None else get_boto_client("dynamodb")

    def get(self, key: str) -> FindingState | None:
        """Retrieve finding state by key."""
        try:
            resp = self._client.get_item(
                TableName=self.table_name,
                Key={"key": {"S": key}},
                ConsistentRead=True,
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            raise RuntimeError(f"DynamoDB get_item failed for key '{key}': {exc}") from exc

        item = resp.get("Item")
        if not item:
            return None
        return self._deserialize(item)

    def put(self, state: FindingState) -> None:
        """Save state using conditional write for optimistic concurrency control.

        - If state.version <= 1: requires attribute_not_exists(key).
        - If state.version > 1: requires version == state.version - 1.
        """
        item = self._serialize(state)

        if state.version <= 1:
            condition = "attribute_not_exists(#k)"
            names = {"#k": "key"}
            values = None
        else:
            condition = "#v = :expected_version"
            names = {"#v": "version"}
            values = {":expected_version": {"N": str(state.version - 1)}}

        put_kwargs: dict[str, Any] = {
            "TableName": self.table_name,
            "Item": item,
            "ConditionExpression": condition,
            "ExpressionAttributeNames": names,
        }
        if values is not None:
            put_kwargs["ExpressionAttributeValues"] = values

        try:
            self._client.put_item(**put_kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                raise OptimisticLockError(
                    f"Conditional write failed for key '{state.key}' with version {state.version}"
                ) from exc
            raise RuntimeError(f"DynamoDB put_item failed for key '{state.key}': {exc}") from exc
        except Exception as exc:
            if "ConditionalCheckFailedException" in type(exc).__name__:
                raise OptimisticLockError(
                    f"Conditional write failed for key '{state.key}' with version {state.version}"
                ) from exc
            raise

    def list_open(self) -> list[FindingState]:
        """Scan table for non-terminal findings."""
        open_states: list[FindingState] = []
        filter_expr = "#s <> :res AND #s <> :act AND #s <> :wld"
        names = {"#s": "status"}
        values = {
            ":res": {"S": FindingStatus.RESOLVED.value},
            ":act": {"S": FindingStatus.ACTED.value},
            ":wld": {"S": FindingStatus.WOULD_ACT.value},
        }

        scan_kwargs: dict[str, Any] = {
            "TableName": self.table_name,
            "FilterExpression": filter_expr,
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
            "ConsistentRead": True,
        }

        try:
            paginator = self._client.get_paginator("scan")
            for page in paginator.paginate(**scan_kwargs):
                for item in page.get("Items", []):
                    st = self._deserialize(item)
                    if st.status == FindingStatus.FAILED and st.attempts >= 3:
                        continue
                    open_states.append(st)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError, AttributeError):
            # Fallback manual scan if get_paginator is not supported
            start_key: dict[str, Any] | None = None
            while True:
                call_kwargs = dict(scan_kwargs)
                if start_key:
                    call_kwargs["ExclusiveStartKey"] = start_key
                resp = self._client.scan(**call_kwargs)
                for item in resp.get("Items", []):
                    st = self._deserialize(item)
                    if st.status == FindingStatus.FAILED and st.attempts >= 3:
                        continue
                    open_states.append(st)
                start_key = resp.get("LastEvaluatedKey")
                if not start_key:
                    break

        return open_states

    def _serialize(self, state: FindingState) -> dict[str, Any]:
        item: dict[str, Any] = {
            "key": {"S": state.key},
            "status": {"S": state.status.value},
            "first_seen": {"S": state.first_seen.astimezone(timezone.utc).isoformat()},
            "last_seen": {"S": state.last_seen.astimezone(timezone.utc).isoformat()},
            "attempts": {"N": str(state.attempts)},
            "version": {"N": str(state.version)},
        }
        if state.warned_at is not None:
            item["warned_at"] = {"S": state.warned_at.astimezone(timezone.utc).isoformat()}
        if state.action_deadline is not None:
            item["action_deadline"] = {
                "S": state.action_deadline.astimezone(timezone.utc).isoformat()
            }
        if state.last_error is not None:
            item["last_error"] = {"S": state.last_error}
        if state.ttl is not None:
            item["ttl"] = {"N": str(state.ttl)}
        if state.metadata:
            item["metadata"] = {"S": json.dumps(state.metadata)}
        return item

    def _deserialize(self, item: dict[str, Any]) -> FindingState:
        first_seen = datetime.fromisoformat(item["first_seen"]["S"])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)

        last_seen = datetime.fromisoformat(item["last_seen"]["S"])
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        warned_at: datetime | None = None
        if "warned_at" in item:
            warned_at = datetime.fromisoformat(item["warned_at"]["S"])
            if warned_at.tzinfo is None:
                warned_at = warned_at.replace(tzinfo=timezone.utc)

        action_deadline: datetime | None = None
        if "action_deadline" in item:
            action_deadline = datetime.fromisoformat(item["action_deadline"]["S"])
            if action_deadline.tzinfo is None:
                action_deadline = action_deadline.replace(tzinfo=timezone.utc)

        last_error = item.get("last_error", {}).get("S")
        ttl = int(item["ttl"]["N"]) if "ttl" in item else None
        attempts = int(item.get("attempts", {}).get("N", "0"))
        version = int(item.get("version", {}).get("N", "1"))

        metadata: dict[str, object] = {}
        if "metadata" in item:
            try:
                metadata = json.loads(item["metadata"]["S"])
            except Exception:
                metadata = {}

        return FindingState(
            key=item["key"]["S"],
            status=FindingStatus(item["status"]["S"]),
            first_seen=first_seen,
            last_seen=last_seen,
            warned_at=warned_at,
            action_deadline=action_deadline,
            attempts=attempts,
            last_error=last_error,
            ttl=ttl,
            version=version,
            metadata=metadata,
        )

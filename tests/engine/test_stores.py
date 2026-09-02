"""Tests for in-memory and DynamoDB StateStore implementations."""

from datetime import datetime, timezone

import boto3
import pytest
from moto import mock_aws

from bill_shock_guard.engine.store_dynamodb import DynamoDbStateStore
from bill_shock_guard.engine.store_memory import MemoryStateStore, OptimisticLockError
from bill_shock_guard.models import FindingState, FindingStatus


def _create_sample_state(
    key: str = "us-east-1#ec2_instance#i-12345",
    status: FindingStatus = FindingStatus.DETECTED,
    version: int = 1,
    attempts: int = 0,
) -> FindingState:
    now = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
    return FindingState(
        key=key,
        status=status,
        first_seen=now,
        last_seen=now,
        version=version,
        attempts=attempts,
        metadata={"instance_type": "t2.micro"},
    )


def test_memory_store_basic_crud() -> None:
    store = MemoryStateStore()
    assert store.get("missing-key") is None

    st = _create_sample_state(version=1)
    store.put(st)

    retrieved = store.get(st.key)
    assert retrieved is not None
    assert retrieved.key == st.key
    assert retrieved.status == FindingStatus.DETECTED
    assert retrieved.version == 1
    assert retrieved.metadata == {"instance_type": "t2.micro"}


def test_memory_store_optimistic_locking() -> None:
    store = MemoryStateStore()
    st = _create_sample_state(version=1)
    store.put(st)

    # Putting again with version 1 should fail (expected version 2)
    with pytest.raises(OptimisticLockError):
        store.put(st)

    # Updating with version 2 should succeed
    st.version = 2
    st.status = FindingStatus.WARNED
    store.put(st)

    # Updating with version 4 (skipping 3) should fail
    st.version = 4
    with pytest.raises(OptimisticLockError):
        store.put(st)


def test_memory_store_list_open() -> None:
    store = MemoryStateStore()

    st_open1 = _create_sample_state(key="k1", status=FindingStatus.DETECTED)
    st_open2 = _create_sample_state(key="k2", status=FindingStatus.WARNED)
    st_open3 = _create_sample_state(key="k3", status=FindingStatus.FAILED, attempts=1)

    st_closed1 = _create_sample_state(key="k4", status=FindingStatus.RESOLVED)
    st_closed2 = _create_sample_state(key="k5", status=FindingStatus.ACTED)
    st_closed3 = _create_sample_state(key="k6", status=FindingStatus.WOULD_ACT)
    st_closed4 = _create_sample_state(key="k7", status=FindingStatus.FAILED, attempts=3)

    for s in [
        st_open1,
        st_open2,
        st_open3,
        st_closed1,
        st_closed2,
        st_closed3,
        st_closed4,
    ]:
        store.put(s)

    open_items = store.list_open()
    open_keys = {item.key for item in open_items}
    assert open_keys == {"k1", "k2", "k3"}
    assert len(store.list_all()) == 7


@mock_aws
def test_dynamodb_store_end_to_end() -> None:
    table_name = "test-bsg-state"
    client = boto3.client("dynamodb", region_name="us-east-1")
    client.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=client)

    # Test get on non-existent item
    assert store.get("non-existent") is None

    # Test insert new item (version 1)
    st = _create_sample_state(key="us-east-1#ec2_instance#i-999", version=1)
    store.put(st)

    fetched = store.get(st.key)
    assert fetched is not None
    assert fetched.key == st.key
    assert fetched.status == FindingStatus.DETECTED
    assert fetched.version == 1
    assert fetched.metadata == {"instance_type": "t2.micro"}

    # Test duplicate insert fails optimistic lock (ConditionExpression attribute_not_exists)
    st_dup = _create_sample_state(key=st.key, version=1)
    with pytest.raises(OptimisticLockError):
        store.put(st_dup)

    # Test update with correct next version (version 2)
    st.version = 2
    st.status = FindingStatus.WARNED
    st.warned_at = datetime(2026, 1, 10, 13, 0, tzinfo=timezone.utc)
    st.action_deadline = datetime(2026, 1, 11, 13, 0, tzinfo=timezone.utc)
    store.put(st)

    updated = store.get(st.key)
    assert updated is not None
    assert updated.status == FindingStatus.WARNED
    assert updated.version == 2
    assert updated.warned_at is not None

    # Test update with stale version fails
    st.version = 2
    with pytest.raises(OptimisticLockError):
        store.put(st)


@mock_aws
def test_dynamodb_store_list_open() -> None:
    table_name = "test-bsg-state-open"
    client = boto3.client("dynamodb", region_name="us-east-1")
    client.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    store = DynamoDbStateStore(table_name=table_name, client=client)

    st_open = _create_sample_state(key="item-open", status=FindingStatus.WARNED)
    st_resolved = _create_sample_state(key="item-resolved", status=FindingStatus.RESOLVED)
    st_acted = _create_sample_state(key="item-acted", status=FindingStatus.ACTED)

    store.put(st_open)
    store.put(st_resolved)
    store.put(st_acted)

    open_items = store.list_open()
    assert len(open_items) == 1
    assert open_items[0].key == "item-open"

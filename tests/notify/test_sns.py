"""Tests for SNSNotifier delivery confirmation, error handling, and subject truncation."""

from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from bill_shock_guard.interfaces import Notifier
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.notify.sns import SNSNotifier

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:my-topic"


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock()
    client.list_subscriptions_by_topic.return_value = {
        "Subscriptions": [{"Protocol": "email", "SubscriptionArn": f"{TOPIC_ARN}:confirmed"}],
    }
    return client


def test_sns_notifier_implements_protocol() -> None:
    notifier = SNSNotifier(topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic")
    assert hasattr(notifier, "name")
    assert hasattr(notifier, "send")
    assert callable(notifier.send)
    assert notifier.name == "sns"
    # Static type check: assignable to Notifier
    type_checked_notifier: Notifier = notifier
    assert type_checked_notifier.name == "sns"


def test_sns_publish_success(mock_client: MagicMock) -> None:
    mock_client.publish.return_value = {
        "MessageId": "msg-12345-abcde",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = SNSNotifier(
        topic_arn="arn:aws:sns:us-east-1:123456789012:my-topic",
        client=mock_client,
        logger=mock_logger,
    )

    result = notifier.send("Test Subject", "Test Body Message")

    assert result is True
    mock_client.publish.assert_called_once_with(
        TopicArn="arn:aws:sns:us-east-1:123456789012:my-topic",
        Subject="Test Subject",
        Message="Test Body Message",
    )
    mock_logger.info.assert_called_once_with(
        "sns_publish_success",
        message_id="msg-12345-abcde",
        topic_arn="arn:aws:sns:us-east-1:123456789012:my-topic",
    )


def test_sns_publish_subject_truncated_to_100_chars(mock_client: MagicMock) -> None:
    mock_client.publish.return_value = {"MessageId": "msg-999"}

    notifier = SNSNotifier(
        topic_arn="arn:aws:sns:us-east-1:123456789012:my-topic",
        client=mock_client,
    )

    long_subject = "A" * 150
    result = notifier.send(long_subject, "Body")

    assert result is True
    call_args = mock_client.publish.call_args[1]
    assert len(call_args["Subject"]) == 100
    assert call_args["Subject"] == "A" * 100


def test_sns_publish_missing_message_id_returns_false(mock_client: MagicMock) -> None:
    # Response without MessageId
    mock_client.publish.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = SNSNotifier(
        topic_arn="arn:aws:sns:us-east-1:123456789012:my-topic",
        client=mock_client,
        logger=mock_logger,
    )

    result = notifier.send("Subject", "Body")
    assert result is False
    mock_logger.error.assert_called_once()


def test_sns_publish_client_error_returns_false_never_crashes(mock_client: MagicMock) -> None:
    error_response = {
        "Error": {
            "Code": "AuthorizationError",
            "Message": "User not authorized to perform sns:Publish",
        }
    }
    mock_client.publish.side_effect = botocore.exceptions.ClientError(error_response, "Publish")

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = SNSNotifier(
        topic_arn="arn:aws:sns:us-east-1:123456789012:my-topic",
        client=mock_client,
        logger=mock_logger,
    )

    # Must catch and return False without raising
    result = notifier.send("Subject", "Body")
    assert result is False
    mock_logger.error.assert_called_once()


def test_sns_requires_confirmed_email_and_paginates(mock_client: MagicMock) -> None:
    notifier = SNSNotifier(topic_arn=TOPIC_ARN, client=mock_client)
    mock_client.list_subscriptions_by_topic.side_effect = [
        {
            "Subscriptions": [
                {"Protocol": "email", "SubscriptionArn": "PendingConfirmation"},
                {"Protocol": "sqs", "SubscriptionArn": f"{TOPIC_ARN}:queue"},
            ],
            "NextToken": "next",
        },
        {"Subscriptions": []},
    ]
    assert not notifier.send("Warning", "Body")
    mock_client.publish.assert_not_called()
    mock_client.list_subscriptions_by_topic.assert_called_with(TopicArn=TOPIC_ARN, NextToken="next")


def test_sns_unconfigured_topic_arn_returns_false() -> None:
    mock_logger = MagicMock(spec=JsonLogger)

    # None topic ARN
    notifier_none = SNSNotifier(topic_arn=None, logger=mock_logger)
    assert notifier_none.send("Subject", "Body") is False
    mock_logger.warning.assert_called_with(
        "sns_publish_skipped",
        reason="SNS topic ARN is not configured",
    )

    # Empty string topic ARN
    notifier_empty = SNSNotifier(topic_arn="", logger=mock_logger)
    assert notifier_empty.send("Subject", "Body") is False


@pytest.mark.parametrize(
    "arn,expected_region",
    [
        ("arn:aws:sns:us-west-2:123456789012:my-topic", "us-west-2"),
        ("arn:aws:sns:ap-south-1:123456789012:alerts", "ap-south-1"),
        ("arn:aws-cn:sns:cn-north-1:123456789012:cn-topic", "cn-north-1"),
        ("invalid-arn-string", "us-east-1"),
        (None, "us-east-1"),
        ("", "us-east-1"),
    ],
)
def test_sns_extract_region(arn: str | None, expected_region: str) -> None:
    region = SNSNotifier._extract_region(arn)
    assert region == expected_region


def test_sns_lazy_client_creation() -> None:
    notifier = SNSNotifier(topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic")
    assert notifier._client is None
    client = notifier.client
    assert client is not None
    # Subsequent access reuses cached client
    assert notifier.client is client

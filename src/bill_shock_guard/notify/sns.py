"""Amazon SNS notifier implementation for Bill Shock Guard."""

import re
from typing import Any

from bill_shock_guard.aws import get_boto_client
from bill_shock_guard.logging_util import JsonLogger


class SNSNotifier:
    """Delivers notification digests via AWS Simple Notification Service (SNS).

    Delivery confirmation semantics:
    A successful send requires a confirmed email subscription and an SNS publish
    acknowledgement. SNS does not confirm inbox delivery.
    """

    name: str = "sns"

    def __init__(
        self,
        topic_arn: str | None,
        client: Any = None,
        region_name: str | None = None,
        logger: JsonLogger | None = None,
    ) -> None:
        self.topic_arn = topic_arn
        self.logger = logger
        self._region = region_name or self._extract_region(topic_arn)
        self._client = client

    @staticmethod
    def _extract_region(arn: str | None) -> str:
        """Extract the AWS region from an SNS topic ARN, falling back to us-east-1."""
        if not arn:
            return "us-east-1"
        # ARN format: arn:aws:sns:<region>:<account-id>:<topic-name>
        match = re.match(r"^arn:aws[a-z0-9-]*:sns:([a-z0-9-]+):", arn)
        if match:
            return match.group(1)
        return "us-east-1"

    @property
    def client(self) -> Any:
        """Lazily obtain or return the injected boto3 SNS client."""
        if self._client is None:
            self._client = get_boto_client("sns", region_name=self._region)
        return self._client

    def send(self, subject: str, body: str) -> bool:
        """Publish digest to SNS topic.

        Returns:
            True if a confirmed email subscription exists and SNS accepts the publish.
        """
        if not self.topic_arn:
            if self.logger:
                self.logger.warning(
                    "sns_publish_skipped",
                    reason="SNS topic ARN is not configured",
                )
            return False

        # SNS subjects cannot exceed 100 characters
        trimmed_subject = subject[:100]

        try:
            if not self._has_confirmed_email(self.topic_arn):
                if self.logger:
                    self.logger.warning("sns_no_confirmed_email_subscription")
                return False
            response = self.client.publish(
                TopicArn=self.topic_arn,
                Subject=trimmed_subject,
                Message=body,
            )
            message_id = response.get("MessageId")
            if message_id:
                if self.logger:
                    self.logger.info(
                        "sns_publish_success",
                        message_id=str(message_id),
                        topic_arn=self.topic_arn,
                    )
                return True

            if self.logger:
                self.logger.error(
                    "sns_publish_failed",
                    reason="Missing MessageId in SNS response",
                    topic_arn=self.topic_arn,
                )
            return False

        except Exception as exc:
            if self.logger:
                self.logger.error(
                    "sns_publish_failed",
                    topic_arn=self.topic_arn,
                    error=str(exc),
                )
            return False

    def _has_confirmed_email(self, topic_arn: str) -> bool:
        args = {"TopicArn": topic_arn}
        while True:
            response = self.client.list_subscriptions_by_topic(**args)
            for subscription in response.get("Subscriptions", []):
                arn = subscription.get("SubscriptionArn", "")
                if subscription.get("Protocol") in {"email", "email-json"} and arn.startswith(
                    f"{topic_arn}:"
                ):
                    return True
            next_token = response.get("NextToken")
            if not next_token:
                return False
            args["NextToken"] = next_token

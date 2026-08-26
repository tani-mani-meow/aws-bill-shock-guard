"""Composite notifier providing fan-out, failure isolation, and I2 delivery semantics."""

from typing import Any, Sequence

from bill_shock_guard.config import Config
from bill_shock_guard.interfaces import Notifier
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.notify.sns import SNSNotifier
from bill_shock_guard.notify.telegram import TelegramNotifier


class CompositeNotifier:
    """Dispatches notifications to multiple channels with failure isolation.

    Invariant I2 delivery semantics:
    Under Invariant I2 ('Never act on a resource unless a warning was successfully
    delivered and recorded at least grace_hours earlier'), delivery is confirmed
    if and only if the baseline channel (SNS) succeeded.

    If SNS is not configured (e.g. local CLI use or unconfigured topic), delivery
    confirmation returns False, keeping the engine in report-only mode so no
    mutating actions are ever taken.
    """

    name: str = "composite"

    def __init__(
        self,
        notifiers: Sequence[Notifier] | None = None,
        baseline_name: str = "sns",
        logger: JsonLogger | None = None,
    ) -> None:
        self.notifiers: list[Notifier] = list(notifiers or [])
        self.baseline_name: str = baseline_name
        self.logger = logger
        self.last_results: dict[str, bool] = {}
        self.last_errors: dict[str, str] = {}

    @classmethod
    def from_config(
        cls,
        config: Config,
        ssm_client: Any = None,
        opener: Any = None,
        logger: JsonLogger | None = None,
    ) -> "CompositeNotifier":
        """Build CompositeNotifier from application configuration."""
        notifiers: list[Notifier] = []

        # Configure SNS notifier
        if config.notify.sns_topic_arn:
            notifiers.append(
                SNSNotifier(
                    topic_arn=config.notify.sns_topic_arn,
                    logger=logger,
                )
            )

        # Configure Telegram notifier if enabled
        if config.notify.telegram.enabled:
            notifiers.append(
                TelegramNotifier(
                    chat_id=config.notify.telegram.chat_id,
                    token_ssm_param=config.notify.telegram.token_ssm_param,
                    ssm_client=ssm_client,
                    opener=opener,
                    logger=logger,
                )
            )

        return cls(notifiers=notifiers, baseline_name="sns", logger=logger)

    def send_detailed(self, subject: str, body: str) -> dict[str, bool]:
        """Dispatch message to all notifiers, isolating failures per notifier.

        Returns:
            Dictionary mapping notifier name to boolean delivery outcome.
        """
        results: dict[str, bool] = {}
        errors: dict[str, str] = {}

        for notifier in self.notifiers:
            n_name = notifier.name
            try:
                ok = notifier.send(subject, body)
                results[n_name] = bool(ok)
                if not ok:
                    errors[n_name] = "Notifier returned delivery failure"
                    if self.logger:
                        self.logger.warning(
                            "notifier_delivery_unconfirmed",
                            notifier=n_name,
                        )
                else:
                    if self.logger:
                        self.logger.info(
                            "notifier_delivery_success",
                            notifier=n_name,
                        )
            except Exception as exc:
                # Per-notifier failure isolation: exceptions must never escape
                results[n_name] = False
                err_str = str(exc)
                errors[n_name] = err_str
                if self.logger:
                    self.logger.error(
                        "notifier_exception_isolated",
                        notifier=n_name,
                        error=err_str,
                    )

        self.last_results = results
        self.last_errors = errors
        return results

    def send(self, subject: str, body: str) -> bool:
        """Send notifications to all channels and evaluate Invariant I2 delivery.

        Returns:
            True if and only if the baseline notifier (SNS) confirmed delivery.
            False if baseline failed or is not configured (report-only mode).
        """
        results = self.send_detailed(subject, body)

        # Baseline channel must exist and must have succeeded
        has_baseline = any(n.name == self.baseline_name for n in self.notifiers)
        if not has_baseline:
            if self.logger:
                self.logger.info(
                    "baseline_notifier_missing",
                    baseline=self.baseline_name,
                    note="Running in report-only mode; delivery unconfirmed for I2",
                )
            return False

        baseline_ok = results.get(self.baseline_name, False)
        return baseline_ok

"""Tests for CompositeNotifier: fan-out, failure isolation, and Invariant I2 delivery semantics."""

from unittest.mock import MagicMock

from bill_shock_guard.config import Config, NotifyConfig, TelegramConfig
from bill_shock_guard.interfaces import Notifier
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.notify.composite import CompositeNotifier


class FakeNotifier:
    """Configurable fake notifier for isolated unit testing."""

    def __init__(
        self,
        name: str,
        return_value: bool = True,
        raise_exception: Exception | None = None,
    ) -> None:
        self.name = name
        self.return_value = return_value
        self.raise_exception = raise_exception
        self.sent_messages: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> bool:
        self.sent_messages.append((subject, body))
        if self.raise_exception:
            raise self.raise_exception
        return self.return_value


def test_composite_notifier_implements_protocol() -> None:
    composite = CompositeNotifier()
    assert composite.name == "composite"
    assert hasattr(composite, "send")
    assert callable(composite.send)
    type_checked: Notifier = composite
    assert type_checked.name == "composite"


def test_composite_from_config() -> None:
    # 1. Config with both SNS and Telegram
    cfg_both = Config(
        notify=NotifyConfig(
            sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            telegram=TelegramConfig(
                enabled=True,
                chat_id="12345",
                token_ssm_param="/bsg/token",
            ),
        )
    )
    comp_both = CompositeNotifier.from_config(cfg_both)
    notifier_names = [n.name for n in comp_both.notifiers]
    assert "sns" in notifier_names
    assert "telegram" in notifier_names
    assert len(comp_both.notifiers) == 2

    # 2. Config with SNS only
    cfg_sns = Config(
        notify=NotifyConfig(
            sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        )
    )
    comp_sns = CompositeNotifier.from_config(cfg_sns)
    assert len(comp_sns.notifiers) == 1
    assert comp_sns.notifiers[0].name == "sns"

    # 3. Config with Telegram only
    cfg_tg = Config(
        notify=NotifyConfig(
            sns_topic_arn=None,
            telegram=TelegramConfig(
                enabled=True,
                chat_id="12345",
                token_ssm_param="/bsg/token",
            ),
        )
    )
    comp_tg = CompositeNotifier.from_config(cfg_tg)
    assert len(comp_tg.notifiers) == 1
    assert comp_tg.notifiers[0].name == "telegram"

    # 4. Config with neither (empty)
    cfg_empty = Config()
    comp_empty = CompositeNotifier.from_config(cfg_empty)
    assert len(comp_empty.notifiers) == 0


def test_composite_fan_out() -> None:
    n1 = FakeNotifier("sns", return_value=True)
    n2 = FakeNotifier("telegram", return_value=True)

    composite = CompositeNotifier(notifiers=[n1, n2])
    results = composite.send_detailed("Subject", "Body")

    assert len(n1.sent_messages) == 1
    assert len(n2.sent_messages) == 1
    assert n1.sent_messages[0] == ("Subject", "Body")
    assert n2.sent_messages[0] == ("Subject", "Body")
    assert results == {"sns": True, "telegram": True}


def test_composite_failure_isolation_exception_in_telegram() -> None:
    """If Telegram throws an unexpected exception, SNS still completes and no exception escapes."""
    n_sns = FakeNotifier("sns", return_value=True)
    n_tg = FakeNotifier("telegram", raise_exception=RuntimeError("Unexpected connection reset"))

    mock_logger = MagicMock(spec=JsonLogger)
    composite = CompositeNotifier(notifiers=[n_tg, n_sns], logger=mock_logger)

    # Calling send should NOT raise RuntimeError
    result = composite.send("Subject", "Body")

    # Telegram threw, but SNS was called and succeeded
    assert len(n_tg.sent_messages) == 1
    assert len(n_sns.sent_messages) == 1
    assert composite.last_results == {"telegram": False, "sns": True}
    assert "Unexpected connection reset" in composite.last_errors["telegram"]

    # Invariant I2: SNS succeeded, so overall delivery confirmed is True
    assert result is True
    mock_logger.error.assert_called_once()


def test_composite_failure_isolation_exception_in_sns() -> None:
    """If SNS throws an unexpected exception, Telegram still completes and no exception escapes."""
    n_sns = FakeNotifier("sns", raise_exception=RuntimeError("SNS API endpoint unreachable"))
    n_tg = FakeNotifier("telegram", return_value=True)

    mock_logger = MagicMock(spec=JsonLogger)
    composite = CompositeNotifier(notifiers=[n_sns, n_tg], logger=mock_logger)

    result = composite.send("Subject", "Body")

    assert len(n_sns.sent_messages) == 1
    assert len(n_tg.sent_messages) == 1
    assert composite.last_results == {"sns": False, "telegram": True}

    # Invariant I2: SNS failed, so overall delivery confirmed is False
    assert result is False


# -----------------------------------------------------------------------------
# Invariant I2 Delivery Semantics Tests
# -----------------------------------------------------------------------------


def test_composite_delivery_unconfirmed_logging() -> None:
    n_sns = FakeNotifier("sns", return_value=False)
    mock_logger = MagicMock(spec=JsonLogger)
    composite = CompositeNotifier(notifiers=[n_sns], logger=mock_logger)

    res = composite.send("Subj", "Body")
    assert res is False
    mock_logger.warning.assert_called_once_with(
        "notifier_delivery_unconfirmed",
        notifier="sns",
    )


def test_composite_baseline_missing_logging() -> None:
    n_tg = FakeNotifier("telegram", return_value=True)
    mock_logger = MagicMock(spec=JsonLogger)
    composite = CompositeNotifier(notifiers=[n_tg], logger=mock_logger)

    res = composite.send("Subj", "Body")
    assert res is False
    mock_logger.info.assert_called_with(
        "baseline_notifier_missing",
        baseline="sns",
        note="Running in report-only mode; delivery unconfirmed for I2",
    )


def test_I2_delivery_confirmed_semantics() -> None:
    """Enforces Invariant I2: 'Never act on a resource unless a warning was successfully delivered'.

    Delivery counts as successful for I2 if and only if SNS (the baseline channel) succeeded.
    If SNS is not configured (e.g. CLI/local report-only mode), send() returns False.
    """
    # Case 1: SNS succeeds, Telegram succeeds -> True
    c1 = CompositeNotifier([FakeNotifier("sns", True), FakeNotifier("telegram", True)])
    assert c1.send("Subject", "Body") is True

    # Case 2: SNS succeeds, Telegram fails -> True (baseline succeeded)
    c2 = CompositeNotifier([FakeNotifier("sns", True), FakeNotifier("telegram", False)])
    assert c2.send("Subject", "Body") is True

    # Case 3: SNS fails, Telegram succeeds -> False (baseline failed)
    c3 = CompositeNotifier([FakeNotifier("sns", False), FakeNotifier("telegram", True)])
    assert c3.send("Subject", "Body") is False

    # Case 4: Both fail -> False
    c4 = CompositeNotifier([FakeNotifier("sns", False), FakeNotifier("telegram", False)])
    assert c4.send("Subject", "Body") is False

    # Case 5: SNS is NOT configured (only Telegram configured) -> False
    # CLI/local mode: engine must run in report-only mode and never act under I2
    c5 = CompositeNotifier([FakeNotifier("telegram", True)])
    assert c5.send("Subject", "Body") is False

    # Case 6: No notifiers configured -> False
    c6 = CompositeNotifier([])
    assert c6.send("Subject", "Body") is False

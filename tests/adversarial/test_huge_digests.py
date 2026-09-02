"""Adversarial tests for huge digests (> 4000 chars), message splitting, and truncation."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from bill_shock_guard.config import Config, NotifyConfig
from bill_shock_guard.engine.runner import EngineRunner
from bill_shock_guard.engine.store_memory import MemoryStateStore
from bill_shock_guard.interfaces import ScanContext
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.models import ActionKind, Finding, FindingStatus, ResourceType
from bill_shock_guard.notify.format import format_digest, format_subject
from bill_shock_guard.notify.sns import SNSNotifier
from bill_shock_guard.notify.telegram import TELEGRAM_MAX_CHARS, TelegramNotifier, split_message
from tests.fakes.fake_clock import FakeClock


def _make_context(clock: FakeClock, config: Config, logger: JsonLogger) -> ScanContext:
    return ScanContext(
        config=config,
        clock=clock,
        account_id="123456789012",
        run_id="test-huge-digest",
        logger=logger,
        client_factory=lambda svc, reg=None: MagicMock(),
    )


def test_split_message_under_limit() -> None:
    """Text under 4000 chars remains a single chunk."""
    text = "Short alert message\nEverything is fine."
    chunks = split_message(text, max_chars=4000)
    assert len(chunks) == 1
    assert chunks[0] == text


def test_split_message_multiline_over_4000_chars() -> None:
    """Multi-line text over 4000 chars is split cleanly at newline boundaries."""
    # 100 lines of 80 chars each = 8000+ chars
    lines = [f"Line {i:04d}: " + ("x" * 70) for i in range(100)]
    full_text = "\n".join(lines)
    assert len(full_text) > 8000

    chunks = split_message(full_text, max_chars=4000)
    assert len(chunks) >= 3

    for idx, chunk in enumerate(chunks):
        assert len(chunk) <= 4000, f"Chunk {idx} exceeded max length: {len(chunk)}"

    # Reconstituted text must match original
    recombined = "\n".join(chunks)
    assert recombined == full_text


def test_split_message_single_monolithic_line_over_4000_chars() -> None:
    """A single unbroken line of 9500 chars (e.g. huge URL/dump) must be sliced safely."""
    monolithic_line = "A" * 9500
    chunks = split_message(monolithic_line, max_chars=4000)
    assert len(chunks) == 3
    assert len(chunks[0]) == 4000
    assert len(chunks[1]) == 4000
    assert len(chunks[2]) == 1500

    # Total characters preserved
    assert "".join(chunks) == monolithic_line


def test_format_digest_with_hundreds_of_findings() -> None:
    """format_digest handles 150 findings (>35,000 characters) without error."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    findings: list[Finding] = []

    for i in range(150):
        action_choice = ActionKind.EC2_STOP if i % 2 == 0 else ActionKind.EBS_DELETE_AFTER_SNAPSHOT
        f = Finding(
            resource_type=ResourceType.EC2_INSTANCE if i % 2 == 0 else ResourceType.EBS_VOLUME,
            resource_id=f"res-{i:04d}",
            region="us-east-1" if i % 3 == 0 else "us-west-2",
            reason=f"Idle resource {i} with extended zero utilization",
            evidence={"metric": i * 0.01},
            est_monthly_cost_usd=15.50,
            cost_confidence="estimate",
            proposed_action=action_choice,
            protected=False,
            protection_reason=None,
            detected_at=now,
        )
        findings.append(f)

    digest = format_digest(findings, dry_run=True, now=now)
    assert len(digest) > 30000
    assert "IDLE RESOURCE WARNINGS (150):" in digest
    assert "Total idle resources flagged: 150" in digest
    # 150 * 15.50 = 2325.00
    assert "approx. $2325.00 USD" in digest


def test_format_subject_strictly_truncated_to_100_chars() -> None:
    """Subject line must never exceed 100 characters even under extreme finding counts/costs."""
    # Extreme scenario
    sub = format_subject(
        findings_count=999999,
        total_cost=987654321.99,
        dry_run=True,
        actions_count=88888,
    )
    assert len(sub) <= 100

    sub_plain = format_subject(
        findings_count=1234567,
        total_cost=None,
        dry_run=False,
    )
    assert len(sub_plain) <= 100


def test_telegram_notifier_splits_and_sends_huge_digest(logger: JsonLogger) -> None:
    """TelegramNotifier splits 12,000 char message into chunks and sends all via POST."""
    mock_opener = MagicMock()
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"ok": True}).encode("utf-8")
    mock_opener.open.return_value = mock_resp

    notifier = TelegramNotifier(
        chat_id="12345678",
        token="test-token-xyz",
        opener=mock_opener,
        logger=logger,
    )

    # 10,000 chars body + subject
    huge_body = "\n".join([f"Line {i:03d}: " + ("A" * 70) for i in range(120)])
    assert len(huge_body) > 9000

    ok = notifier.send(subject="Important Alert", body=huge_body)
    assert ok is True

    # Check chunks sent
    assert mock_opener.open.call_count >= 3
    for call in mock_opener.open.call_args_list:
        req = call[0][0]
        data = json.loads(req.data.decode("utf-8"))
        assert data["chat_id"] == "12345678"
        assert len(data["text"]) <= TELEGRAM_MAX_CHARS


def test_telegram_notifier_fails_if_any_chunk_fails(logger: JsonLogger) -> None:
    """If delivery of any chunk fails in a multi-chunk message, send() returns False."""
    mock_opener = MagicMock()

    # First chunk succeeds, second chunk fails
    resp_ok = MagicMock()
    resp_ok.read.return_value = json.dumps({"ok": True}).encode("utf-8")

    resp_fail = MagicMock()
    fail_payload = json.dumps({"ok": False, "description": "Rate limited"}).encode("utf-8")
    resp_fail.read.return_value = fail_payload

    mock_opener.open.side_effect = [resp_ok, resp_fail, resp_fail]

    notifier = TelegramNotifier(
        chat_id="12345678",
        token="test-token-xyz",
        opener=mock_opener,
        logger=logger,
    )

    huge_body = "Line: " + ("B" * 3990) + "\nLine: " + ("C" * 3990)
    assert len(huge_body) > 7000

    ok = notifier.send(subject="", body=huge_body)
    # Delivery unconfirmed under Invariant I2
    assert ok is False


def test_sns_notifier_truncates_subject_and_delivers_huge_body(logger: JsonLogger) -> None:
    """SNSNotifier ensures subject is <= 100 chars and publishes full huge body."""
    mock_sns = MagicMock()
    mock_sns.publish.return_value = {"MessageId": "msg-123456"}
    mock_sns.list_subscriptions_by_topic.return_value = {
        "Subscriptions": [
            {
                "Protocol": "email",
                "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:test-topic:confirmed",
            },
        ],
    }

    notifier = SNSNotifier(
        topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        client=mock_sns,
        logger=logger,
    )

    oversized_subject = "A" * 150
    huge_body = "Resource data\n" * 500

    ok = notifier.send(subject=oversized_subject, body=huge_body)
    assert ok is True

    mock_sns.publish.assert_called_once()
    call_kwargs = mock_sns.publish.call_args[1]
    assert len(call_kwargs["Subject"]) <= 100
    assert call_kwargs["Subject"] == "A" * 100
    assert call_kwargs["Message"] == huge_body


def test_engine_runner_huge_digest_all_warnings_recorded(
    fake_clock: FakeClock,
    logger: JsonLogger,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EngineRunner processes 50 findings, formats digest, and records all WARNED states."""
    cfg = Config(
        dry_run=True,
        regions=["us-east-1"],
        notify=NotifyConfig(sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic"),
    )
    ctx = _make_context(fake_clock, cfg, logger)
    store = MemoryStateStore()
    monkeypatch.setattr(
        "bill_shock_guard.engine.runner.get_enabled_regions", lambda **kwargs: ["us-east-1"]
    )

    findings = [
        Finding(
            resource_type=ResourceType.EC2_INSTANCE,
            resource_id=f"i-batch-{i:03d}",
            region="us-east-1",
            reason="Idle EC2 instance",
            evidence={},
            est_monthly_cost_usd=10.0,
            cost_confidence="estimate",
            proposed_action=ActionKind.EC2_STOP,
            protected=False,
            protection_reason=None,
            detected_at=fake_clock.now(),
        )
        for i in range(50)
    ]

    mock_detector = MagicMock()
    mock_detector.resource_type = ResourceType.EC2_INSTANCE
    mock_detector.detect.return_value = findings

    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True

    runner = EngineRunner(detectors=[mock_detector], actions={})
    summary = runner.run(ctx, store, notifier=mock_notifier)

    assert summary.findings_detected == 50
    assert summary.warnings_sent == 50
    assert mock_notifier.send.call_count == 1

    subject, body = mock_notifier.send.call_args[0]
    assert len(body) > 5000  # verified huge digest
    assert summary.errors == []

    # All 50 states are now in WARNED status
    open_states = store.list_open()
    assert len(open_states) == 50
    for st in open_states:
        assert st.status == FindingStatus.WARNED

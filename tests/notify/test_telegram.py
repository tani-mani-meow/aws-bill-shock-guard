"""Tests for TelegramNotifier: message splitting, token secrecy, and HTTP retry logic."""

import json
import urllib.error
import urllib.request
from unittest.mock import MagicMock

from bill_shock_guard.interfaces import Notifier
from bill_shock_guard.logging_util import JsonLogger
from bill_shock_guard.notify.telegram import TelegramNotifier, split_message

SECRET_TOKEN = "mock_telegram_bot_token_sample_12345"
CHAT_ID = "987654321"


class MockHttpResponse:
    """Mock HTTP response object for urllib.request opener."""

    def __init__(self, data: bytes, status: int = 200) -> None:
        self.data = data
        self.status = status
        self.code = status

    def read(self) -> bytes:
        return self.data


# -----------------------------------------------------------------------------
# 1. Message Splitting Tests
# -----------------------------------------------------------------------------


def test_split_message_under_4000_chars() -> None:
    text = "Short alert message under limit"
    chunks = split_message(text, max_chars=4000)
    assert len(chunks) == 1
    assert chunks[0] == text


def test_split_message_exact_4000_chars() -> None:
    text = "x" * 4000
    chunks = split_message(text, max_chars=4000)
    assert len(chunks) == 1
    assert len(chunks[0]) == 4000


def test_split_message_over_4000_chars_at_line_boundaries() -> None:
    line_len = 100
    line = "A" * (line_len - 1) + "\n"
    # 50 lines of 100 chars = 5000 chars
    text = line * 50

    chunks = split_message(text, max_chars=4000)
    assert len(chunks) >= 2
    for chunk in chunks:
        assert len(chunk) <= 4000
        # Verify no lines were chopped mid-line
        for chunk_line in chunk.split("\n"):
            assert len(chunk_line) in (line_len - 1, 0)


def test_split_message_single_line_exceeding_max_chars() -> None:
    # A single giant line without newlines
    long_line = "B" * 9500
    chunks = split_message(long_line, max_chars=4000)

    assert len(chunks) == 3
    assert len(chunks[0]) == 4000
    assert len(chunks[1]) == 4000
    assert len(chunks[2]) == 1500
    assert "".join(chunks) == long_line


def test_split_message_mixed_multiline() -> None:
    part1 = "Line 1\nLine 2\n"
    long_block = "C" * 4500
    part2 = "\nLine 3\nLine 4"
    full_text = part1 + long_block + part2

    chunks = split_message(full_text, max_chars=4000)
    for chunk in chunks:
        assert len(chunk) <= 4000


# -----------------------------------------------------------------------------
# 2. Token Secrecy Tests (Logs and Exceptions)
# -----------------------------------------------------------------------------


def test_token_secrecy_never_in_logs() -> None:
    # Set up mock logger
    mock_logger = MagicMock(spec=JsonLogger)
    mock_opener = MagicMock()
    # Opener raises an error containing the secret URL
    error_url = f"https://api.telegram.org/bot{SECRET_TOKEN}/sendMessage"
    mock_opener.open.side_effect = urllib.error.URLError(f"Failed to connect to {error_url}")

    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
        logger=mock_logger,
    )

    result = notifier.send("Subject", "Body")
    assert result is False

    # Check all calls made to logger (info, warning, error)
    for call in mock_logger.mock_calls:
        call_str = str(call)
        assert SECRET_TOKEN not in call_str

    # Verify redaction took place in the logged warning error argument
    warning_calls_str = str(mock_logger.warning.call_args_list)
    assert "[REDACTED]" in warning_calls_str


def test_token_secrecy_never_in_repr() -> None:
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
    )
    repr_str = repr(notifier)
    assert SECRET_TOKEN not in repr_str
    assert "[REDACTED]" in repr_str


def test_sanitize_method() -> None:
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
    )
    raw_error = f"HTTP 401 Unauthorized for https://api.telegram.org/bot{SECRET_TOKEN}/sendMessage"
    sanitized = notifier._sanitize(raw_error)

    assert SECRET_TOKEN not in sanitized
    assert "https://api.telegram.org/bot[REDACTED]/sendMessage" in sanitized


# -----------------------------------------------------------------------------
# 3. HTTP Mock Tests (Opener injection, no real network, no parse_mode)
# -----------------------------------------------------------------------------


def test_telegram_send_success_no_parse_mode() -> None:
    mock_opener = MagicMock()
    success_json = json.dumps({"ok": True, "result": {"message_id": 42}}).encode("utf-8")
    mock_opener.open.return_value = MockHttpResponse(success_json, status=200)

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
        timeout=10.0,
        logger=mock_logger,
    )

    result = notifier.send("Alert Subject", "Alert Body")
    assert result is True

    # Verify opener was called with Request
    assert mock_opener.open.call_count == 1
    call_args = mock_opener.open.call_args
    req = call_args[0][0]
    timeout = call_args[1]["timeout"]

    assert isinstance(req, urllib.request.Request)
    assert timeout == 10.0
    assert req.method == "POST"

    # Verify JSON payload has chat_id and text, but NO parse_mode
    assert isinstance(req.data, bytes)
    payload = json.loads(req.data.decode("utf-8"))
    assert payload["chat_id"] == CHAT_ID
    assert "Alert Subject" in payload["text"]
    assert "Alert Body" in payload["text"]
    assert "parse_mode" not in payload, "Telegram notification must NOT specify parse_mode"


def test_telegram_retry_on_failure_succeeds_on_second_attempt() -> None:
    mock_opener = MagicMock()
    success_json = json.dumps({"ok": True}).encode("utf-8")

    # 1st attempt fails, 2nd attempt succeeds
    mock_opener.open.side_effect = [
        urllib.error.URLError("Temporary network blip"),
        MockHttpResponse(success_json, status=200),
    ]

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
        logger=mock_logger,
    )

    result = notifier.send("Subject", "Body")
    assert result is True
    # Verify exactly 2 attempts (initial + 1 retry)
    assert mock_opener.open.call_count == 2
    mock_logger.warning.assert_called_once()
    mock_logger.info.assert_called_once()


def test_telegram_retry_exhausted_returns_false() -> None:
    mock_opener = MagicMock()
    # Both attempt 1 and retry attempt 2 fail
    mock_opener.open.side_effect = [
        urllib.error.URLError("Connection timed out"),
        urllib.error.URLError("Connection timed out again"),
    ]

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
        logger=mock_logger,
    )

    result = notifier.send("Subject", "Body")
    assert result is False
    assert mock_opener.open.call_count == 2
    mock_logger.error.assert_called_once()


def test_telegram_split_multi_chunk_send() -> None:
    mock_opener = MagicMock()
    success_json = json.dumps({"ok": True}).encode("utf-8")
    mock_opener.open.return_value = MockHttpResponse(success_json, status=200)

    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
    )

    # Message exceeding 4000 characters
    long_body = "Line of text\n" * 400  # ~5200 characters
    result = notifier.send("Long Subject", long_body)

    assert result is True
    assert mock_opener.open.call_count == 2


# -----------------------------------------------------------------------------
# 4. SSM SecureString Retrieval Tests
# -----------------------------------------------------------------------------


def test_ssm_securestring_retrieval_and_caching() -> None:
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {
        "Parameter": {
            "Name": "/bsg/telegram_token",
            "Type": "SecureString",
            "Value": SECRET_TOKEN,
        }
    }

    mock_opener = MagicMock()
    success_json = json.dumps({"ok": True}).encode("utf-8")
    mock_opener.open.return_value = MockHttpResponse(success_json, status=200)

    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token_ssm_param="/bsg/telegram_token",
        ssm_client=mock_ssm,
        opener=mock_opener,
    )

    # 1st send: fetches token with WithDecryption=True
    res1 = notifier.send("Subject 1", "Body 1")
    assert res1 is True
    mock_ssm.get_parameter.assert_called_once_with(
        Name="/bsg/telegram_token",
        WithDecryption=True,
    )

    # 2nd send: uses cached token, does NOT call SSM again
    res2 = notifier.send("Subject 2", "Body 2")
    assert res2 is True
    assert mock_ssm.get_parameter.call_count == 1


def test_ssm_failure_returns_false_and_sanitizes() -> None:
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.side_effect = Exception("ParameterNotFound: /bsg/secret")

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token_ssm_param="/bsg/secret",
        ssm_client=mock_ssm,
        logger=mock_logger,
    )

    result = notifier.send("Subject", "Body")
    assert result is False
    mock_logger.error.assert_called_once()


def test_missing_chat_id_or_token_returns_false() -> None:
    # Empty chat ID
    n_no_chat = TelegramNotifier(chat_id="", token="some-token")
    assert n_no_chat.send("Subject", "Body") is False

    # Missing token and no ssm param
    n_no_token = TelegramNotifier(chat_id="12345", token=None, token_ssm_param=None)
    assert n_no_token.send("Subject", "Body") is False


def test_telegram_send_without_subject_and_success_logging() -> None:
    mock_opener = MagicMock()
    success_json = json.dumps({"ok": True}).encode("utf-8")
    mock_opener.open.return_value = MockHttpResponse(success_json, status=200)

    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token=SECRET_TOKEN,
        opener=mock_opener,
        logger=mock_logger,
    )

    # Empty subject
    res = notifier.send("", "Standalone body without subject")
    assert res is True
    mock_logger.info.assert_called_once_with("telegram_send_success", parts=1)

    req = mock_opener.open.call_args[0][0]
    assert isinstance(req.data, bytes)
    payload = json.loads(req.data.decode("utf-8"))
    assert payload["text"] == "Standalone body without subject"


def test_ssm_empty_param_val_returns_false() -> None:
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {
        "Parameter": {
            "Name": "/bsg/token",
            "Value": "",  # Empty string
        }
    }
    mock_logger = MagicMock(spec=JsonLogger)
    notifier = TelegramNotifier(
        chat_id=CHAT_ID,
        token_ssm_param="/bsg/token",
        ssm_client=mock_ssm,
        logger=mock_logger,
    )

    res = notifier.send("Subj", "Body")
    assert res is False
    mock_logger.error.assert_called_once_with(
        "telegram_ssm_empty",
        ssm_param="/bsg/token",
    )


def test_telegram_implements_protocol() -> None:
    notifier = TelegramNotifier(chat_id="12345", token="token")
    assert notifier.name == "telegram"
    assert callable(notifier.send)
    type_checked: Notifier = notifier
    assert type_checked.name == "telegram"

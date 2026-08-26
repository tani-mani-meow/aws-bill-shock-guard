"""Telegram notifier implementation using urllib.request and SSM SecureString."""

import json
import re
import urllib.error
import urllib.request
from typing import Any

from bill_shock_guard.aws import get_boto_client
from bill_shock_guard.logging_util import JsonLogger

TELEGRAM_MAX_CHARS = 4000
DEFAULT_TIMEOUT_SECONDS = 10.0


def split_message(text: str, max_chars: int = TELEGRAM_MAX_CHARS) -> list[str]:
    """Split message into segments of at most max_chars at newline boundaries."""
    if len(text) <= max_chars:
        return [text]

    lines = text.split("\n")
    chunks: list[str] = []
    current_lines: list[str] = []
    current_length = 0

    for line in lines:
        if len(line) > max_chars:
            if current_lines:
                chunks.append("\n".join(current_lines))
                current_lines = []
                current_length = 0

            start = 0
            while start < len(line):
                slice_chunk = line[start : start + max_chars]
                if len(slice_chunk) == max_chars and (start + max_chars < len(line)):
                    chunks.append(slice_chunk)
                else:
                    current_lines.append(slice_chunk)
                    current_length = len(slice_chunk)
                start += max_chars
            continue

        needed = len(line) if not current_lines else len(line) + 1
        if current_length + needed > max_chars:
            chunks.append("\n".join(current_lines))
            current_lines = [line]
            current_length = len(line)
        else:
            current_lines.append(line)
            current_length += needed

    if current_lines:
        chunks.append("\n".join(current_lines))

    return chunks


class TelegramNotifier:
    """Delivers plain-text notification digests via the Telegram Bot API.

    Safety & Secrecy rules:
    - Token is read from SSM SecureString or injected at initialization.
    - Token is cached in memory and NEVER logged or exposed in exceptions.
    - Plain text only; no parse_mode (avoids Markdown/HTML injection and escaping errors).
    - Messages over 4000 characters are split at line boundaries.
    - Network timeout is 10 seconds with exactly one retry on failure.
    - Uses urllib.request (stdlib only, no third-party HTTP libraries).
    - Supports injectable opener for testing without real network calls.
    """

    name: str = "telegram"

    def __init__(
        self,
        chat_id: str,
        token: str | None = None,
        token_ssm_param: str | None = None,
        ssm_client: Any = None,
        opener: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        logger: JsonLogger | None = None,
        region_name: str | None = None,
    ) -> None:
        self.chat_id = chat_id
        self.token_ssm_param = token_ssm_param
        self.ssm_client = ssm_client
        self.opener = opener
        self.timeout = timeout
        self.logger = logger
        self._region = region_name or "us-east-1"
        self._token: str | None = token

    def __repr__(self) -> str:
        return f"TelegramNotifier(chat_id={self.chat_id!r}, token='[REDACTED]')"

    def _sanitize(self, text: str) -> str:
        """Strip bot token from any string, URL, or exception text."""
        sanitized = text
        if self._token:
            sanitized = sanitized.replace(self._token, "[REDACTED]")
        # Redact any bot token in standard Telegram URLs
        sanitized = re.sub(
            r"api\.telegram\.org/bot[^/]+/", "api.telegram.org/bot[REDACTED]/", sanitized
        )
        return sanitized

    def _get_token(self) -> str | None:
        """Retrieve token from cache or fetch from SSM Parameter Store (SecureString)."""
        if self._token:
            return self._token

        if not self.token_ssm_param:
            if self.logger:
                self.logger.warning(
                    "telegram_token_missing",
                    reason="Neither token nor token_ssm_param configured",
                )
            return None

        try:
            client = self.ssm_client or get_boto_client("ssm", region_name=self._region)
            resp = client.get_parameter(Name=self.token_ssm_param, WithDecryption=True)
            param_val = resp.get("Parameter", {}).get("Value")
            if param_val:
                self._token = param_val
                return self._token

            if self.logger:
                self.logger.error(
                    "telegram_ssm_empty",
                    ssm_param=self.token_ssm_param,
                )
            return None

        except Exception as exc:
            if self.logger:
                self.logger.error(
                    "telegram_ssm_fetch_failed",
                    ssm_param=self.token_ssm_param,
                    error=self._sanitize(str(exc)),
                )
            return None

    def _post_chunk(self, chunk: str, token: str) -> bool:
        """Send a single message chunk with timeout and one retry."""
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": chunk,
            # Explicitly NO parse_mode to avoid formatting/escaping breakage
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )

        opener = self.opener or urllib.request.build_opener()

        for attempt in (1, 2):
            try:
                resp = opener.open(req, timeout=self.timeout)
                resp_bytes = resp.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                if resp_json.get("ok") is True:
                    return True

                err_desc = self._sanitize(str(resp_json.get("description", "Unknown error")))
                if self.logger:
                    self.logger.warning(
                        "telegram_send_attempt_failed",
                        attempt=attempt,
                        error=err_desc,
                    )
            except Exception as exc:
                err_msg = self._sanitize(str(exc))
                if self.logger:
                    self.logger.warning(
                        "telegram_send_attempt_error",
                        attempt=attempt,
                        error=err_msg,
                    )

            if attempt == 2:
                if self.logger:
                    self.logger.error(
                        "telegram_send_failed",
                        reason="Failed after 1 retry",
                    )
                return False

        return False

    def send(self, subject: str, body: str) -> bool:
        """Send plain-text message to Telegram chat, splitting at 4000 characters.

        Returns:
            True if all parts were successfully delivered.
            False if credentials are missing or sending any part failed.
        """
        if not self.chat_id:
            if self.logger:
                self.logger.warning("telegram_send_skipped", reason="chat_id not configured")
            return False

        token = self._get_token()
        if not token:
            return False

        # Format complete message combining subject and body
        full_text = f"{subject}\n\n{body}" if subject else body
        chunks = split_message(full_text, max_chars=TELEGRAM_MAX_CHARS)

        for chunk in chunks:
            ok = self._post_chunk(chunk, token)
            if not ok:
                return False

        if self.logger:
            self.logger.info("telegram_send_success", parts=len(chunks))
        return True

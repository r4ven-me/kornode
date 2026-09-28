from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

from kornode.config.models import OtpAuthConfig


class OtpDeliveryService:
    def __init__(self, settings: OtpAuthConfig) -> None:
        self.settings = settings

    def send_test_email(self) -> None:
        cfg = self.settings
        if not cfg.smtp_host or not cfg.smtp_from or not cfg.smtp_test_recipient:
            raise ValueError("SMTP host, from address and test recipient are required")
        message = EmailMessage()
        message["Subject"] = f"{cfg.issuer} OTP email test"
        message["From"] = cfg.smtp_from
        message["To"] = cfg.smtp_test_recipient
        message.set_content("Korvus Node OTP email delivery is configured correctly.")

        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as client:
            if cfg.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
            if cfg.smtp_username:
                if not cfg.smtp_password:
                    raise ValueError("SMTP password is required when SMTP username is configured")
                client.login(cfg.smtp_username, cfg.smtp_password)
            client.send_message(message)

    def send_test_telegram(self) -> None:
        cfg = self.settings
        if not cfg.telegram_bot_token or not cfg.telegram_chat_id:
            raise ValueError("Telegram bot token and chat ID are required")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
            data=json.dumps(
                {
                    "chat_id": cfg.telegram_chat_id,
                    "text": f"{cfg.issuer}: OTP Telegram delivery is configured correctly.",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Telegram API returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ValueError(f"Telegram API request failed: {exc.reason}") from exc
        if not payload.get("ok"):
            raise ValueError(f"Telegram API rejected the message: {payload}")

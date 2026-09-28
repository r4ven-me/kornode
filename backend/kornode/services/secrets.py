from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

SECRET_KEY_RE = re.compile(
    r"(password|passphrase|passwd|token|secret|private[_-]?key|cert[_-]?pass|admin_password)",
    re.IGNORECASE,
)
SECRET_REF_VALUE_RE = re.compile(r"\$\{SECRET:[^}]+}")
ASSIGNMENT_RE = re.compile(r"(?m)^([ \t]*)([A-Za-z0-9_.-]+)([ \t]*[:=][ \t]*)(.+)$")
NON_SECRET_KEYS = {
    "secret_dir",
    "secrets_dir",
    "secret_path",
    "secrets_path",
    # server.camouflage.secret is a shared TLS camouflage password, not a
    # per-user credential; the UI displays it in plain text like any other
    # setting instead of masking/round-tripping it like a real secret. Its
    # structural (JSON/YAML) field name is "secret" -- see CamouflageConfig.
    "secret",
}
# mask_text() additionally exempts the *rendered ocserv.conf directive name*
# for that same field ("camouflage_secret = ..." -- see
# templates/ocserv.conf.j2), which is a different string from the
# structural key above. This must NOT be part of NON_SECRET_KEYS itself:
# UpstreamProfileConfig.camouflage_secret is a completely different,
# genuinely sensitive field (a shared credential for reaching the
# *upstream* server) that happens to have the exact same key name, and
# is_secret_key()/redact_value() -- used to mask structured config dumps
# like AppConfig.model_dump_safe(), not rendered text -- must still treat
# it as secret.
_TEXT_ONLY_NON_SECRET_KEYS = NON_SECRET_KEYS | {"camouflage_secret"}


def is_secret_key(key: str) -> bool:
    if key.lower() in NON_SECRET_KEYS:
        return False
    return bool(SECRET_KEY_RE.search(key))


def _is_secret_key_in_text(key: str) -> bool:
    if key.lower() in _TEXT_ONLY_NON_SECRET_KEYS:
        return False
    return bool(SECRET_KEY_RE.search(key))


def redact_value(value: Any, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {
            item_key: redact_value(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_value(item) for item in value]
    if key is not None and is_secret_key(key) and value not in {None, "", False}:
        return "***"
    if isinstance(value, str):
        return SECRET_REF_VALUE_RE.sub("${SECRET:***}", value)
    return value


def mask_text(text: str, secrets: Sequence[str] | None = None) -> str:
    masked = SECRET_REF_VALUE_RE.sub("${SECRET:***}", text)
    for secret in secrets or []:
        if secret:
            masked = masked.replace(secret, "***")

    def redact_assignment(match: re.Match[str]) -> str:
        key = match.group(2)
        if not _is_secret_key_in_text(key):
            return match.group(0)
        return f"{match.group(1)}{key}{match.group(3)}***"

    return ASSIGNMENT_RE.sub(redact_assignment, masked)


def collect_config_secrets(config: Any) -> list[str]:
    try:
        data = config.model_dump(mode="json")
    except AttributeError:
        data = config

    found: list[str] = []

    def walk(value: Any, key: str | None = None) -> None:
        if isinstance(value, Mapping):
            for item_key, item_value in value.items():
                walk(item_value, str(item_key))
            return
        if isinstance(value, list | tuple):
            for item in value:
                walk(item, key)
            return
        if key is not None and is_secret_key(key) and isinstance(value, str) and value:
            found.append(value)
        if key == "port" and isinstance(value, str) and "?" in value:
            found.append(value.split("?", 1)[1])

    walk(data)
    return found

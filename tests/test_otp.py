from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.otp import OtpService


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )


def test_enable_then_disable_round_trips(tmp_path: Path) -> None:
    service = OtpService(_config(tmp_path))

    secret = service.enable("alice")

    assert service.secret_for_user("alice") == secret
    assert service.disable("alice") is True
    assert service.secret_for_user("alice") is None


def test_concurrent_enable_calls_do_not_lose_changes(tmp_path: Path) -> None:
    # Regression test: enable()/disable() read-modify-write the whole
    # users.oath file, and uvicorn serves API requests on parallel threads
    # -- without a lock (the same hazard users.py's _PASSWD_REWRITE_LOCK
    # protects against for ocpasswd), concurrent enable() calls for
    # different users would each read the same original file and the last
    # write would silently discard the others' additions.
    service = OtpService(_config(tmp_path))
    usernames = [f"user{i}" for i in range(8)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(service.enable, username) for username in usernames]
        for future in futures:
            future.result()

    for username in usernames:
        assert service.secret_for_user(username) is not None

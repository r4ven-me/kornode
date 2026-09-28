from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kornode.api import auth as auth_module
from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.services.password_hash import hash_password


def _client() -> TestClient:
    config = AppConfig.model_validate({"web": {"admin_password": "secret"}})
    return TestClient(create_app(config))


def test_protected_api_requires_basic_auth() -> None:
    response = _client().get("/api/config")

    assert response.status_code == 401
    assert "www-authenticate" not in response.headers
    assert response.json()["detail"] == "authentication required"


def test_invalid_credentials_do_not_trigger_browser_basic_prompt() -> None:
    response = _client().get("/api/config", auth=("admin", "wrong"))

    assert response.status_code == 401
    assert "www-authenticate" not in response.headers
    assert response.json()["detail"] == "invalid credentials"


def test_protected_api_accepts_valid_basic_auth() -> None:
    response = _client().get("/api/config", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["web"]["admin_password"] == "***"


def test_auth_me_returns_authenticated_identity() -> None:
    response = _client().get("/api/auth/me", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": True,
        "username": "admin",
        "csrf_token": None,
    }


def test_cookie_session_requires_csrf_for_mutations(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            AppConfig.model_validate(
                {
                    "system": {
                        "data_dir": str(tmp_path / "data"),
                        "generated_dir": str(tmp_path / "generated"),
                        "log_dir": str(tmp_path / "logs"),
                        "secrets_dir": str(tmp_path / "secrets"),
                    },
                    "web": {"admin_password": "secret"},
                }
            )
        ),
        base_url="https://testserver",
    )
    login_response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret"},
    )
    csrf_token = login_response.json()["csrf_token"]

    rejected = client.post("/api/config/render")
    accepted = client.post(
        "/api/config/render",
        headers={"X-Kornode-CSRF": csrf_token},
    )

    assert login_response.status_code == 200
    assert login_response.cookies.get("kornode_session")
    assert rejected.status_code == 403
    assert accepted.status_code == 200


def test_protected_api_accepts_hashed_admin_password() -> None:
    config = AppConfig.model_validate(
        {"web": {"admin_password_hash": hash_password("secret")}}
    )
    response = TestClient(create_app(config)).get("/api/config", auth=("admin", "secret"))

    assert response.status_code == 200


def _mutation_client(tmp_path: Path) -> TestClient:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "web": {"admin_password": "secret"},
        }
    )
    return TestClient(create_app(config))


def test_basic_auth_mutation_rejected_with_mismatched_origin(tmp_path: Path) -> None:
    # Regression test: require_admin()'s CSRF check used to only run for the
    # cookie-session branch, leaving Basic-Auth-authenticated mutations
    # completely unprotected -- a browser that ever authenticated with
    # Basic Auth resends those cached credentials automatically on any
    # request to this origin, including one triggered by a third-party
    # page's plain <form method=post>, making every mutating endpoint
    # cross-site exploitable.
    response = _mutation_client(tmp_path).post(
        "/api/config/render",
        auth=("admin", "secret"),
        headers={"Origin": "https://evil.example.com"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "cross-origin request rejected"


def test_basic_auth_mutation_allowed_with_matching_origin(tmp_path: Path) -> None:
    response = _mutation_client(tmp_path).post(
        "/api/config/render",
        auth=("admin", "secret"),
        headers={"Origin": "http://testserver"},
    )

    assert response.status_code == 200


def test_basic_auth_mutation_allowed_without_origin_header(tmp_path: Path) -> None:
    # A legitimate non-browser API client (curl, a script) typically sends
    # neither Origin nor Referer at all -- only a header that's present AND
    # names a different host should be rejected.
    response = _mutation_client(tmp_path).post("/api/config/render", auth=("admin", "secret"))

    assert response.status_code == 200


def test_totp_code_guesses_are_rate_limited(tmp_path: Path) -> None:
    # Regression test: the password step was already rate-limited, but a
    # wrong TOTP code never recorded a failure -- once an attacker had (or
    # guessed/leaked) the admin password, the 6-digit code itself was
    # brute-forceable with unlimited attempts.
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "web": {
                "admin_password": "secret",
                "admin_totp_enabled": True,
                "admin_totp_secret": "JBSWY3DPEHPK3PXP",
            },
        }
    )
    client = TestClient(create_app(config))

    responses = [
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "secret", "totp_code": "000000"},
        )
        for _ in range(6)
    ]

    assert [response.status_code for response in responses[:5]] == [401] * 5
    assert responses[5].status_code == 429


def test_totp_code_required_response_does_not_count_toward_the_lockout(tmp_path: Path) -> None:
    # The frontend's normal flow calls /login without a code first and gets
    # this response before prompting for one -- it must not burn the
    # 5-per-5min lockout budget on every ordinary login.
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "web": {
                "admin_password": "secret",
                "admin_totp_enabled": True,
                "admin_totp_secret": "JBSWY3DPEHPK3PXP",
            },
        }
    )
    client = TestClient(create_app(config))

    responses = [
        client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
        for _ in range(6)
    ]

    assert all(response.status_code == 401 for response in responses)
    assert all(response.json()["detail"] == "totp_code_required" for response in responses)


def test_session_expires_after_the_absolute_lifetime_even_if_actively_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression test: get() used to reset expires_at = now + lifetime on
    # every use with no upper bound, so a stolen/leaked session cookie
    # stayed valid indefinitely as long as it was replayed periodically --
    # ABSOLUTE_SESSION_LIFETIME_MULTIPLIER now caps the total lifetime
    # regardless of activity.
    now = 1000.0
    monkeypatch.setattr(auth_module.time, "monotonic", lambda: now)
    registry = auth_module.AuthSessionRegistry(lifetime_seconds=10)
    token, _ = registry.create("admin")

    # Still well within the sliding lifetime AND the 4x absolute cap (40s).
    now += 5
    assert registry.get(token) is not None

    # Past the absolute cap (40s from creation) -- rejected even though it
    # was "used" a moment ago and its sliding expires_at would otherwise
    # still be far in the future.
    now = 1000.0 + auth_module.ABSOLUTE_SESSION_LIFETIME_MULTIPLIER * 10 + 1
    assert registry.get(token) is None


def test_session_slides_within_the_absolute_lifetime(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sliding renewal on activity is still the point of expires_at -- only
    # the absolute cap should ever cut a session short.
    now = 1000.0
    monkeypatch.setattr(auth_module.time, "monotonic", lambda: now)
    registry = auth_module.AuthSessionRegistry(lifetime_seconds=10)
    token, _ = registry.create("admin")

    # Past the original 10s sliding window, but each `get()` call renews it
    # -- well under the 40s absolute cap throughout.
    for _ in range(3):
        now += 8
        assert registry.get(token) is not None

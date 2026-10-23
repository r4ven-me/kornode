from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kornode import cli
from kornode.api.app import create_app
from kornode.config.loader import load_config, load_yaml_file
from kornode.services.config import ConfigService


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, inherited: bool = False
) -> tuple[Path, dict[str, Any]]:
    path = tmp_path / "config.yaml"
    collections: dict[str, Any] = {
        "upstream": {
            "profiles": [
                {
                    "name": name,
                    "server": "vpn.example.com",
                    "username": name,
                    "password": "${SECRET:PROFILE_PASSWORD}",
                }
                for name in ("first", "second")
            ]
        },
        "identity": {
            "oidc_providers": [
                {
                    "name": name,
                    "issuer_url": "https://id.example.com",
                    "client_id": name,
                    "client_secret": "${SECRET:OIDC_SECRET}",
                }
                for name in ("first", "second")
            ],
            "group_policies": [{"name": name} for name in ("first", "second")],
        },
    }
    raw = {
        "system": {
            key: str(tmp_path / key)
            for key in ("data_dir", "generated_dir", "log_dir", "secrets_dir")
        },
        "web": {"admin_password": "${SECRET:ADMIN_PASSWORD}"},
    }
    env = (
        "ADMIN_PASSWORD=admin-test-password\nPROFILE_PASSWORD=profile-test-password\n"
        "OIDC_SECRET=oidc-test-secret\nLATEST_SECRET=latest-test-secret\n"
    )
    if inherited:
        for section, fields in collections.items():
            for field, value in fields.items():
                env += f"KORNODE_{section.upper()}__{field.upper()}={json.dumps(value)}\n"
    else:
        raw.update(collections)
    path.write_text(yaml.safe_dump(raw))
    path.with_name(".env").write_text(env)
    # Exercise real source locking/validation/publication, without unrelated runtime effects.
    monkeypatch.setattr(ConfigService, "render_files", lambda *_: [])
    monkeypatch.setattr(ConfigService, "write_rendered_files", lambda *_: [])
    monkeypatch.setitem(cli.STATE, "config_path", path)
    monkeypatch.setitem(cli.STATE, "env_file", path.with_name(".env"))
    return path, collections


@pytest.mark.parametrize("inherited", [False, True], ids=["yaml", "env"])
@pytest.mark.parametrize("operation", ["profile", "provider", "group-set", "group-delete"])
def test_cli_collection_mutates_latest_raw_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, inherited: bool
) -> None:
    path, collections = _setup(tmp_path, monkeypatch, inherited=inherited)
    group_file = tmp_path / "group.yaml"
    group_file.write_text("name: first\ndisplay_name: CLI group\n")
    commands = {
        "profile": ["upstream", "disable", "first"],
        "provider": [
            "identity",
            "oidc",
            "provider-set",
            "first",
            "--issuer-url",
            "https://updated.example.com",
            "--client-id",
            "updated",
        ],
        "group-set": ["identity", "group", "set", "--file", str(group_file)],
        "group-delete": ["identity", "group", "delete", "first"],
    }
    section, field = {
        "profile": ("upstream", "profiles"),
        "provider": ("identity", "oidc_providers"),
        "group-set": ("identity", "group_policies"),
        "group-delete": ("identity", "group_policies"),
    }[operation]
    latest = collections[section][field]
    concurrent = {**latest[1], "name": "concurrent"}
    secret_field = {"profile": "password", "provider": "client_secret"}.get(operation)
    if secret_field:
        latest[0][secret_field] = "${SECRET:LATEST_SECRET}"
    else:
        latest[1]["display_name"] = "API change"
    latest.append(concurrent)
    entered, committed = Event(), Event()
    original = cli.mutate_config

    def interleave(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        assert committed.wait(10), "API save did not finish"
        return original(*args, **kwargs)

    monkeypatch.setattr(cli, "mutate_config", interleave)
    client = TestClient(create_app(config_path=path))

    def api_save() -> None:
        assert entered.wait(10), "CLI did not enter save"
        try:
            response = client.patch(
                "/api/config",
                auth=("admin", "admin-test-password"),
                json={"patch": {section: {field: latest}}, "write_rendered": False},
            )
            assert response.status_code == 200, response.text
        finally:
            committed.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        winner = pool.submit(api_save)
        result = CliRunner().invoke(
            cli.app,
            [
                "--config",
                str(path),
                "--env-file",
                str(path.with_name(".env")),
                *commands[operation],
            ],
        )
        winner.result(timeout=15)
    assert result.exit_code == 0, result.output
    saved = load_yaml_file(path)
    items = saved[section][field]
    assert [item["name"] for item in items] == (
        ["second", "concurrent"]
        if operation == "group-delete"
        else ["first", "second", "concurrent"]
    )
    if secret_field:
        assert items[0][secret_field] == "${SECRET:LATEST_SECRET}"
        assert (
            items[1][secret_field]
            == items[2][secret_field]
            == ("${SECRET:PROFILE_PASSWORD}" if operation == "profile" else "${SECRET:OIDC_SECRET}")
        )
    else:
        assert next(item for item in items if item["name"] == "second")["display_name"] == (
            "API change"
        )
    if operation == "profile":
        assert items[0]["enabled"] is False
    if operation == "provider":
        assert items[0]["client_id"] == "updated"
    if operation == "group-set":
        assert items[0]["display_name"] == "CLI group"
    assert saved["web"]["admin_password"] == "${SECRET:ADMIN_PASSWORD}"
    text = path.read_text()
    assert not any(
        secret in text
        for secret in (
            "profile-test-password",
            "oidc-test-secret",
            "latest-test-secret",
            "admin-test-password",
        )
    )
    load_config(path)


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ([], "${SECRET:OIDC_SECRET}"),
        (["--clear-client-secret"], None),
        (["--client-secret", ""], ""),
        (["--client-secret", "${SECRET:LATEST_SECRET}"], "${SECRET:LATEST_SECRET}"),
    ],
)
def test_oidc_secret_omitted_clear_empty_and_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, options: list[str], expected: str | None
) -> None:
    path, _ = _setup(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        cli.app,
        [
            "--config",
            str(path),
            "identity",
            "oidc",
            "provider-set",
            "first",
            "--issuer-url",
            "https://id.example.com",
            "--client-id",
            "updated",
            *options,
        ],
    )
    assert result.exit_code == 0, result.output
    providers = load_yaml_file(path)["identity"]["oidc_providers"]
    assert providers[0]["client_secret"] == expected
    assert providers[1]["client_secret"] == "${SECRET:OIDC_SECRET}"
    assert "oidc-test-secret" not in result.output
    assert "latest-test-secret" not in result.output


def test_oidc_secret_clear_and_set_are_mutually_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _setup(tmp_path, monkeypatch)
    before = path.read_bytes()
    result = CliRunner().invoke(
        cli.app,
        [
            "--config",
            str(path),
            "identity",
            "oidc",
            "provider-set",
            "first",
            "--issuer-url",
            "https://id.example.com",
            "--client-id",
            "updated",
            "--clear-client-secret",
            "--client-secret",
            "do-not-save",
        ],
    )
    assert result.exit_code != 0
    assert path.read_bytes() == before

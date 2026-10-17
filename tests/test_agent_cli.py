from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from tests.test_agent_apply import World

from kornode_agent.cli import main
from kornode_agent.config import AgentConfig, HubConfig, save_config
from kornode_agent.enroll import is_enrolled
from kornode_agent.inspection import Redactor
from kornode_agent.store import atomic_write


def enrolled(world: World) -> Path:
    root = world.store.root
    save_config(
        root,
        AgentConfig(
            node_id=3,
            hub=HubConfig(
                host="hub",
                port=443,
                pin="pin-sha256:test",
                control_url="https://10.99.0.1:8444",
                camouflage="hide-this-camouflage",
            ),
        ),
    )
    from cryptography.hazmat.primitives import serialization

    atomic_write(
        root / "seal/x25519.key",
        world.seal.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    return root


def call(root: Path, *args: str) -> int:
    return main(["--root", str(root), *args])


def test_offline_status_and_bundle_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    w = World(tmp_path)
    w.applier.boot()
    root = enrolled(w)
    w.applier.apply_bundle(*w.bundle(5))
    assert call(root, "status", "--json") == 0
    status = json.loads(capsys.readouterr().out)
    assert status["running"] is False and status["hub_reachable"] is None
    assert status["applied_version"] == 5 and status["tunnels"] is None
    assert call(root, "bundle", "history", "--json") == 0
    rows = json.loads(capsys.readouterr().out)["bundles"]
    assert rows[0]["version"] == 5 and rows[0]["result"] == "current"
    assert not is_enrolled(root)  # inspection does not manufacture TLS identity


def test_show_verifies_signature_and_redacts_all_secrets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    w = World(tmp_path)
    w.applier.boot()
    root = enrolled(w)
    body, sig = w.bundle(5)
    w.applier.apply_bundle(body, sig)
    original = copy.deepcopy(json.loads(body))
    assert call(root, "bundle", "show", "--json") == 0
    shown = capsys.readouterr().out
    assert "[redacted]" in shown
    for value in (
        original["tunnels"]["upstreams"][0]["password"]["ct"],
        original["access"]["server_key"]["ct"],
        original["access"]["users"][0]["pw_hash"],
    ):
        assert value not in shown
    assert json.loads(shown)["version"] == 5
    (root / "bundles/5.json").write_bytes(body + b" ")
    assert call(root, "bundle", "show", "5", "--json") == 3
    error = json.loads(capsys.readouterr().out)
    assert error["error"] == "invalid_bundle"


@pytest.mark.parametrize(
    "args",
    [
        ["explain", "host", "not-an-ip"],
        ["bundle", "rollback", "-1"],
        ["explain", "host", "1.1.1.1", "--port", "70000"],
        ["unknown"],
    ],
)
def test_usage_errors_are_json_and_never_echo_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: list[str]
) -> None:
    assert call(tmp_path, *args, "--json") == 2
    out = capsys.readouterr()
    assert out.err == ""
    assert json.loads(out.out)["error"] == "usage"


@pytest.mark.parametrize(
    "args",
    [
        ["doctor"],
        ["diag"],
        ["reconnect"],
        ["explain", "host", "1.1.1.1"],
        ["bundle", "rollback", "1"],
    ],
)
def test_runtime_actions_do_not_start_a_second_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: list[str]
) -> None:
    assert call(tmp_path, *args, "--json") == 1
    assert json.loads(capsys.readouterr().out)["error"] == "agent_unavailable"
    assert not (tmp_path / "state.json").exists()


def test_version_json_any_position(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "--root", str(tmp_path), "version"]) == 0
    assert "agent" in json.loads(capsys.readouterr().out)


def test_redactor_masks_structured_and_known_secrets() -> None:
    redactor = Redactor(["unlabelled-secret", "camouflage-value"])
    text = """password="a secret with spaces" token: abc
Authorization: Bearer access-token
Cookie: webvpn=cookie-data; path=/
https://vpn.test/?camouflage-value
-----BEGIN PRIVATE KEY-----
private-key-data
-----END PRIVATE KEY-----
{"pw_hash": "hash-value", "server_key": {"ct": "sealed-data"}}
unlabelled-secret
private_key="other-key-material" passwd='other-password'"""
    safe = redactor.text(text)
    for value in (
        "a secret with spaces",
        "abc",
        "access-token",
        "cookie-data",
        "camouflage-value",
        "private-key-data",
        "hash-value",
        "sealed-data",
        "unlabelled-secret",
        "other-key-material",
        "other-password",
    ):
        assert value not in safe


@pytest.mark.parametrize(
    "command,reply,code",
    [
        (["status"], {"running": True, "hub_reachable": True}, 0),
        (["status"], {"running": True, "hub_reachable": False}, 4),
        (["doctor"], {"findings": []}, 0),
        (["doctor"], {"findings": [{"severity": "warning"}]}, 0),
        (["doctor"], {"findings": [{"severity": "error"}]}, 1),
        (["explain", "host", "1.1.1.1"], {"route": "main table"}, 0),
        (["reconnect", "fabric"], {"reconnected": ["fabric"]}, 0),
        (["bundle", "rollback", "5"], {"result": "confirmed"}, 0),
    ],
)
def test_cli_runtime_dispatch_and_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
    reply: dict[str, object],
    code: int,
) -> None:
    monkeypatch.setattr("kornode_agent.cli.request", lambda root, req: reply)
    assert call(tmp_path, *command, "--json") == code
    assert json.loads(capsys.readouterr().out) == reply


def test_diag_output_atomic_private_and_no_clobber(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import base64

    from kornode_agent.inspection import write_archive
    from kornode_agent.local import LocalError

    data = b"an archive"
    monkeypatch.setattr(
        "kornode_agent.cli.request",
        lambda root, req: {
            "archive_b64": base64.b64encode(data).decode(),
        },
    )
    path = tmp_path / "diag.tar.gz"
    assert call(tmp_path, "diag", "--out", str(path), "--json") == 0
    assert path.read_bytes() == data and path.stat().st_mode & 0o777 == 0o600
    capsys.readouterr()
    assert call(tmp_path, "diag", "--out", str(path), "--json") == 3
    assert json.loads(capsys.readouterr().out)["error"] == "output_exists"
    assert path.read_bytes() == data
    link = tmp_path / "dangling.tar.gz"
    target = tmp_path / "absent"
    link.symlink_to(target)
    with pytest.raises(LocalError):
        write_archive(link, data)
    assert not target.exists() and link.is_symlink()
    assert not list(tmp_path.glob(".*.tmp"))


def test_force_enroll_refused_while_running(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kornode_agent.local import ProcessLock

    with ProcessLock(tmp_path):
        assert call(tmp_path, "enroll", "sensitive-token", "--force", "--json") == 3
    output = capsys.readouterr()
    assert "sensitive-token" not in output.out + output.err
    assert json.loads(output.out)["error"] == "already_running"


def test_human_output_and_usage_do_not_dump_tracebacks(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert call(tmp_path, "version") == 0
    assert "agent:" in capsys.readouterr().out
    assert call(tmp_path, "enroll", "sensitive-token") == 2
    output = capsys.readouterr()
    assert "sensitive-token" not in output.out + output.err
    assert "usage:" in output.err


def test_redactor_escaped_quotes_and_partial_key_tail() -> None:
    value = '{"password": "first\\"trailing-secret", "token": "a\\\\b"}\n' + "A" * 64
    safe = Redactor().text(value)
    assert "trailing-secret" not in safe and "A" * 64 not in safe

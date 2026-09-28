from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


def _client(config_path: Path, tmp_path: Path, extra: str = "") -> TestClient:
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
web:
  enabled: true
  admin_password: secret
auth:
  password:
    enabled: true
{extra}
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_delete_group_removes_config_policy_and_membership(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(
        config_path,
        tmp_path,
        extra=(
            "identity:\n"
            "  group_policies:\n"
            "    - name: devops\n"
            "      routes: [10.20.0.0/16]\n"
        ),
    )

    # A config-per-group file for the same group.
    save = client.put(
        "/api/groups/devops/config",
        auth=("admin", "secret"),
        json={"dns": ["10.10.10.1"]},
    )
    assert save.status_code == 200

    # Two users, one of them a member of the group being deleted.
    passwd = tmp_path / "secrets" / "ocpasswd"
    passwd.parent.mkdir(parents=True)
    passwd.write_text("alice:devops:$5$hash\nbob:sre:$5$hash\n", encoding="utf-8")

    before = client.get("/api/groups", auth=("admin", "secret")).json()
    assert any(group["name"] == "devops" for group in before)

    response = client.delete("/api/groups/devops", auth=("admin", "secret"))
    assert response.status_code == 200

    # Config file gone.
    assert not (tmp_path / "generated" / "config-per-group" / "devops").exists()

    # Removed from the persisted group_policies list.
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved.get("identity", {}).get("group_policies", []) == []

    # Cleared from alice's membership, bob untouched.
    passwd_content = passwd.read_text(encoding="utf-8")
    assert "alice:$5$hash" in passwd_content
    assert "bob:sre:$5$hash" in passwd_content

    after = client.get("/api/groups", auth=("admin", "secret")).json()
    assert all(group["name"] != "devops" for group in after)


def test_delete_group_with_nothing_to_remove_still_succeeds(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.delete("/api/groups/ghost", auth=("admin", "secret"))

    assert response.status_code == 200
    assert "nothing to remove" in response.json()["stdout"]


def test_delete_group_rejects_invalid_name(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.delete("/api/groups/bad!name", auth=("admin", "secret"))

    assert response.status_code == 400

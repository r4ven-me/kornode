from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from kornode.config.models import AppConfig, GroupPolicyConfig
from kornode.services.files import FileManager
from kornode.services.groups import GroupConfigService
from kornode.services.users import UserConfig, UserService


@pytest.mark.parametrize("name", [".", ".."])
def test_dot_and_dotdot_group_names_are_rejected(tmp_path: Path, name: str) -> None:
    # Regression test: group_config_path() appends no filename suffix, so an
    # unsanitized "." or ".." would resolve to the per-group config
    # directory itself or its parent -- see the analogous UserService test.
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
        }
    )

    with pytest.raises(ValueError, match="letters, numbers"):
        GroupConfigService(config).group_config_path(name)


def test_group_config_service_writes_config_per_group(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
            "identity": {"config_per_group_dir": tmp_path / "generated" / "groups"},
        }
    )

    result = GroupConfigService(config).save_group_config(
        "devops",
        UserConfig(dns=["10.10.10.1"], routes=["10.20.0.0/16"], tunnel_all_dns=True),
    )

    assert result.returncode == 0
    rendered = (tmp_path / "generated" / "groups" / "devops").read_text(encoding="utf-8")
    assert "dns = 10.10.10.1" in rendered
    assert "route = 10.20.0.0/16" in rendered
    assert "tunnel-all-dns = true" in rendered


def test_saving_an_empty_group_config_still_creates_the_group(tmp_path: Path) -> None:
    # Regression test: creating a group via the UI with no settings yet
    # (just a name) must still register the group so it shows up and can
    # have members added, rather than silently doing nothing.
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
            "identity": {"config_per_group_dir": tmp_path / "generated" / "groups"},
        }
    )
    service = GroupConfigService(config)

    result = service.save_group_config("infra", UserConfig())

    assert result.returncode == 0
    assert (tmp_path / "generated" / "groups" / "infra").exists()
    groups = service.list_groups()
    assert [group.name for group in groups] == ["infra"]
    assert groups[0].config_exists is True
    assert groups[0].has_settings is False


def test_user_groups_are_written_between_username_and_hash(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text("alice:$5$hash\n", encoding="utf-8")

    UserService(config).set_user_groups("alice", ["devops", "sre"])

    assert passwd.read_text(encoding="utf-8") == "alice:devops,sre:$5$hash\n"
    assert UserService(config).read_user_groups("alice") == ["devops", "sre"]


def test_reserved_group_names_are_rejected_for_user_membership(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )

    with pytest.raises(ValueError, match="group 'agents' is reserved"):
        UserService(config).set_user_groups("alice", ["agents"])


def test_reserved_group_policy_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="group 'enroll' is reserved"):
        GroupPolicyConfig.model_validate({"name": "enroll"})


def test_user_groups_do_not_parse_password_hash_as_group(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text("alice::$5$hash\nbob:devops:$5$hash\n", encoding="utf-8")

    service = UserService(config)

    assert service.read_user_groups("alice") == []
    assert service.read_user_groups("bob") == ["devops"]


def test_user_created_without_a_group_can_still_be_added_to_one(tmp_path: Path) -> None:
    # Regression test: `ocpasswd -c file username` (no -g) writes the
    # single-character placeholder "*" as ocserv's own "no group" marker.
    # Before the fix, that placeholder was parsed back as a real group name,
    # so adding such a user to any group failed validation on the stale "*".
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text("wh1te:*:$5$hash\n", encoding="utf-8")

    service = UserService(config)
    assert service.read_user_groups("wh1te") == []

    service.set_user_groups("wh1te", ["infra"])

    assert service.read_user_groups("wh1te") == ["infra"]


def test_ensure_default_group_adds_only_missing_groups_and_preserves_disabled(
    tmp_path: Path,
) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text(
        "alice:$5$hash\nbob:devops:$5$hash\n!carol:$5$hash\n",
        encoding="utf-8",
    )

    changed = UserService(config).ensure_default_group()

    assert changed == ["alice", "carol"]
    assert passwd.read_text(encoding="utf-8") == (
        "alice:clients:$5$hash\nbob:devops:$5$hash\n!carol:clients:$5$hash\n"
    )


def test_ensure_default_group_dry_run_does_not_write(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text("alice:$5$hash\n", encoding="utf-8")

    changed = UserService(config).ensure_default_group(dry_run=True)

    assert changed == ["alice"]
    assert passwd.read_text(encoding="utf-8") == "alice:$5$hash\n"


def test_ensure_default_group_skips_write_when_nothing_changes(tmp_path: Path) -> None:
    class RecordingFiles(FileManager):
        def __init__(self) -> None:
            self.writes: int = 0

        def atomic_write_private_text(self, path: Path, content: str) -> None:
            self.writes += 1
            super().atomic_write_private_text(path, content)

    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    passwd.write_text("alice:clients:$5$hash\n", encoding="utf-8")
    files = RecordingFiles()

    changed = UserService(config, files=files).ensure_default_group()

    assert changed == []
    assert files.writes == 0


def test_concurrent_group_updates_do_not_lose_changes(tmp_path: Path) -> None:
    # Regression test: the group-members dialog saves one request per changed
    # user, and uvicorn serves them on parallel threads. Each request rewrites
    # the whole passwd file, so without locking the last write discarded the
    # other users' membership changes.
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    passwd = config.secret_path("ocpasswd")
    passwd.parent.mkdir(parents=True)
    usernames = [f"user{i}" for i in range(8)]
    passwd.write_text(
        "".join(f"{username}:$5$hash\n" for username in usernames),
        encoding="utf-8",
    )
    service = UserService(config)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(service.set_user_groups, username, ["infra"]) for username in usernames
        ]
        for future in futures:
            future.result()

    for username in usernames:
        assert service.read_user_groups(username) == ["infra"]

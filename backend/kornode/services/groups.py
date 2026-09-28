from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.files import FileManager
from kornode.services.users import USERNAME_RE, UserConfig, UserService


@dataclass(frozen=True)
class GroupConfigRecord:
    name: str
    config_exists: bool
    has_settings: bool


class GroupConfigService:
    def __init__(
        self,
        config: AppConfig,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.files = files or FileManager()
        self.user_config = UserService(config, files=self.files)

    def validate_group_name(self, name: str) -> str:
        if not USERNAME_RE.match(name):
            raise ValueError(f"group '{name}' may contain letters, numbers, _, ., @ and - only")
        return name

    def group_config_dir(self) -> Path:
        return self.config.identity.config_per_group_dir or (
            self.config.system.generated_dir / "config-per-group"
        )

    def group_config_path(self, name: str) -> Path:
        return self.group_config_dir() / self.validate_group_name(name)

    def list_groups(self) -> list[GroupConfigRecord]:
        names = {group.name for group in self.config.identity.group_policies}
        directory = self.group_config_dir()
        if directory.exists():
            names.update(
                path.name
                for path in directory.iterdir()
                if path.is_file() and not path.name.startswith(".")
            )
        result = []
        for name in sorted(names):
            path = self.group_config_path(name)
            exists = path.exists()
            result.append(
                GroupConfigRecord(
                    name=name,
                    config_exists=exists,
                    has_settings=exists and not self.read_group_config(name).is_empty(),
                )
            )
        return result

    def read_group_config(self, name: str) -> UserConfig:
        path = self.group_config_path(name)
        return UserConfig.model_validate(self.user_config.parse_user_config_file(path))

    def save_group_config(self, name: str, group_config: UserConfig) -> CommandResult:
        # Always persist, even when group_config is empty: a group's mere
        # existence (so it can be listed and have members added) must not
        # depend on it also having ocserv-level settings. Use delete_group_config
        # to actually remove a group.
        path = self.group_config_path(name)
        self.files.ensure_dir(path.parent, mode=0o700)
        self.files.atomic_write_private_text(
            path,
            self.user_config.render_user_config(group_config),
        )
        return CommandResult(
            ("korctl", "identity", "group", "config", "save", name),
            0,
            f"written {path}\n",
            "",
        )

    def delete_group_config(self, name: str) -> bool:
        path = self.group_config_path(name)
        if not path.exists():
            return False
        path.unlink()
        return True

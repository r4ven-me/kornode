from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kornode.config.models import DOMAIN_RE, AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager

# The negative lookahead rejects exactly "." or ".." (but not e.g. "john.doe"
# or "...", which have no special meaning to the filesystem): username- and
# group-derived paths (user_config_path()/group_config_path() below) append
# no filename suffix, so an unsanitized "." or ".." would resolve to the
# config directory itself or its parent.
USERNAME_RE = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9_.@-]{1,64}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
PORT_RULE_RE = re.compile(r"^[A-Za-z0-9_(),!:\s-]+$")

# Serializes Python-side read-modify-write cycles on the ocpasswd file:
# concurrent API requests (uvicorn handles sync routes in a threadpool)
# would otherwise each read the same original file and the last write
# would discard the earlier ones.
_PASSWD_REWRITE_LOCK = threading.Lock()


def _validate_ip(value: str) -> str:
    ipaddress.ip_address(value)
    return value


def _validate_network(value: str) -> str:
    ipaddress.ip_network(value, strict=False)
    return value


def _validate_route(value: str) -> str:
    if value == "default":
        return value
    if "/" in value:
        left, right = value.split("/", 1)
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            ipaddress.ip_address(left)
            ipaddress.ip_address(right)
            return value
    return _validate_network(value)


def _validate_domain(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or not DOMAIN_RE.match(candidate):
        raise ValueError(f"invalid domain name: {value}")
    return candidate


def _strip_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_bool(value: str) -> bool | None:
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "1", "on"}:
        return True
    if lowered in {"false", "no", "0", "off"}:
        return False
    return None


def _parse_int(value: str) -> int | None:
    try:
        return int(value.strip(), 10)
    except ValueError:
        return None


@dataclass(frozen=True)
class UserRecord:
    username: str
    disabled: bool = False
    certificate_exists: bool = False
    p12_exists: bool = False
    groups: list[str] | None = None


@dataclass(frozen=True)
class _PasswdRecord:
    username: str
    fields: list[str]
    disabled: bool
    groups: list[str]


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dns: list[str] = Field(default_factory=list)
    nbns: list[str] = Field(default_factory=list)
    split_dns: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    no_routes: list[str] = Field(default_factory=list)
    iroutes: list[str] = Field(default_factory=list)
    ipv4_network: str | None = None
    ipv4_netmask: str | None = None
    ipv6_network: str | None = None
    ipv6_subnet_prefix: int | None = Field(default=None, ge=1, le=128)
    explicit_ipv4: str | None = None
    explicit_ipv6: str | None = None
    rx_data_per_sec: int | None = Field(default=None, ge=0)
    tx_data_per_sec: int | None = Field(default=None, ge=0)
    net_priority: str | None = None
    deny_roaming: bool | None = None
    no_udp: bool | None = None
    keepalive: int | None = Field(default=None, ge=0)
    dpd: int | None = Field(default=None, ge=0)
    mobile_dpd: int | None = Field(default=None, ge=0)
    max_same_clients: int | None = Field(default=None, ge=1)
    tunnel_all_dns: bool | None = None
    restrict_user_to_routes: bool | None = None
    stats_report_time: int | None = Field(default=None, ge=0)
    mtu: int | None = Field(default=None, ge=576, le=65535)
    idle_timeout: int | None = Field(default=None, ge=1)
    mobile_idle_timeout: int | None = Field(default=None, ge=1)
    restrict_user_to_ports: str | None = None
    session_timeout: int | None = Field(default=None, ge=1)
    hostname: str | None = None

    @field_validator(
        "ipv4_network",
        "ipv6_network",
        mode="before",
    )
    @classmethod
    def validate_optional_network(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        return _validate_network(stripped) if stripped else None

    @field_validator("ipv4_netmask", "explicit_ipv4", mode="before")
    @classmethod
    def validate_optional_ipv4(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        if stripped:
            address = ipaddress.ip_address(stripped)
            if address.version != 4:
                raise ValueError("expected IPv4 address")
        return stripped

    @field_validator("explicit_ipv6", mode="before")
    @classmethod
    def validate_optional_ipv6(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        if stripped:
            address = ipaddress.ip_address(stripped)
            if address.version != 6:
                raise ValueError("expected IPv6 address")
        return stripped

    @field_validator("dns", "nbns")
    @classmethod
    def validate_ips(cls, value: list[str]) -> list[str]:
        return [_validate_ip(item.strip()) for item in value if item.strip()]

    @field_validator("split_dns")
    @classmethod
    def validate_split_dns(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value if item.strip()]

    @field_validator("routes", "no_routes", "iroutes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        return [_validate_route(item.strip()) for item in value if item.strip()]

    @field_validator("net_priority", mode="before")
    @classmethod
    def validate_net_priority(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        if stripped and int(stripped, 0) < 0:
            raise ValueError("net-priority must be non-negative")
        return stripped

    @field_validator("restrict_user_to_ports", mode="before")
    @classmethod
    def validate_port_rules(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        if stripped and not PORT_RULE_RE.match(stripped):
            raise ValueError("restrict-user-to-ports contains unsupported characters")
        return stripped

    @field_validator("hostname", mode="before")
    @classmethod
    def validate_hostname(cls, value: str | None) -> str | None:
        stripped = _strip_optional(value)
        if stripped and not HOSTNAME_RE.match(stripped):
            raise ValueError("hostname must be a valid DNS hostname")
        return stripped

    @model_validator(mode="after")
    def validate_ipv4_pair(self) -> UserConfig:
        if self.ipv4_netmask and not self.ipv4_network:
            raise ValueError("ipv4-netmask requires ipv4-network")
        return self

    def is_empty(self) -> bool:
        return not any(
            value not in (None, [], "")
            for value in self.model_dump(mode="python").values()
        )


class UserService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.passwd_file = config.secret_path("ocpasswd")

    def validate_username(self, username: str) -> str:
        if not USERNAME_RE.match(username):
            raise ValueError(
                f"username '{username}' may contain letters, numbers, _, ., @ and - only"
            )
        return username

    def validate_group_name(self, group: str) -> str:
        if not USERNAME_RE.match(group):
            raise ValueError(f"group '{group}' may contain letters, numbers, _, ., @ and - only")
        return group

    def list_users(self) -> list[UserRecord]:
        records: list[UserRecord] = []
        for line in self.files.read_lines(self.passwd_file):
            if not line or line.startswith("#") or ":" not in line:
                continue
            record = self._parse_passwd_record(line)
            clean_username = record.username
            user_cert = self.config.system.data_dir / "certs" / "users" / f"{clean_username}.crt"
            user_p12 = self.config.system.data_dir / "certs" / "users" / f"{clean_username}.p12"
            records.append(
                UserRecord(
                    username=clean_username,
                    disabled=record.disabled,
                    certificate_exists=user_cert.exists(),
                    p12_exists=user_p12.exists(),
                    groups=record.groups,
                )
            )
        return records

    def read_user_groups(self, username: str) -> list[str]:
        self.validate_username(username)
        for record in self.list_users():
            if record.username == username:
                return record.groups or []
        return []

    def set_user_groups(self, username: str, groups: list[str]) -> CommandResult:
        self.validate_username(username)
        clean_groups = []
        for group in groups:
            stripped = group.strip()
            if stripped:
                clean_groups.append(self.validate_group_name(stripped))
        with _PASSWD_REWRITE_LOCK:
            lines = self.files.read_lines(self.passwd_file)
            changed = False
            next_lines: list[str] = []
            for line in lines:
                record = self._parse_passwd_record(line)
                if record.username != username:
                    next_lines.append(line)
                    continue
                next_lines.append(self._render_passwd_record(record, clean_groups))
                changed = True
            if changed:
                self.files.atomic_write_private_text(
                    self.passwd_file,
                    "\n".join(next_lines) + ("\n" if next_lines else ""),
                )
        return CommandResult(
            ("korctl", "user", "groups", "set", username),
            0,
            f"groups for {username}: {', '.join(clean_groups) if clean_groups else 'none'}\n",
            "",
        )

    @staticmethod
    def _parse_groups_field(value: str) -> list[str]:
        clean = value.lstrip("!")
        # ocserv/ocpasswd treat single-character group placeholders (e.g. "*"
        # written by `ocpasswd` for a user created without -g) as "no group"
        # and ignore them; do the same, otherwise they leak into
        # set_user_groups() as a bogus group name and fail validation.
        return [
            item.strip()
            for item in re.split(r"[,;]", clean)
            if item.strip() and len(item.strip()) > 1
        ]

    def _parse_passwd_record(self, line: str) -> _PasswdRecord:
        fields = line.split(":")
        username = fields[0].lstrip("!") if fields else ""
        tail = fields[1:]
        disabled = fields[0].startswith("!") if fields else False
        disabled = disabled or any(field.startswith("!") for field in tail)
        group_field = ""
        second_field_is_legacy_lock = (
            len(tail) >= 2
            and tail[1].startswith("!")
            and not self._looks_like_password_hash(tail[1])
        )
        if (
            len(tail) >= 2
            and not second_field_is_legacy_lock
            and not self._looks_like_password_hash(tail[0])
        ):
            group_field = tail[0]
        return _PasswdRecord(
            username=username,
            fields=fields,
            disabled=disabled,
            groups=self._parse_groups_field(group_field),
        )

    @staticmethod
    def _looks_like_password_hash(value: str) -> bool:
        stripped = value.lstrip("!")
        if stripped == "":
            return False
        return stripped.startswith("$") or len(stripped) > 32

    def _render_passwd_record(self, record: _PasswdRecord, groups: list[str]) -> str:
        fields = [*record.fields]
        if len(fields) <= 1:
            return ":".join(fields)
        group_value = ",".join(groups)
        if len(fields) == 2:
            if group_value:
                return ":".join([fields[0], group_value, fields[1]])
            return ":".join(fields)
        fields[1] = group_value
        if not group_value:
            return ":".join([fields[0], *fields[2:]])
        return ":".join(fields)

    def _passwd_argv(self, *args: str) -> list[str]:
        return ["ocpasswd", "-c", str(self.passwd_file), *args]

    def user_config_dir(self) -> Path:
        if self.config.identity.config_per_user_dir is None:
            return self.config.system.generated_dir / "config-per-user"
        return self.config.identity.config_per_user_dir

    def user_config_path(self, username: str) -> Path:
        self.validate_username(username)
        return self.user_config_dir() / username

    def read_user_config(self, username: str) -> UserConfig:
        path = self.user_config_path(username)
        return UserConfig.model_validate(self._parse_user_config(path))

    def save_user_config(self, username: str, user_config: UserConfig) -> CommandResult:
        path = self.user_config_path(username)
        if user_config.is_empty():
            deleted = self.delete_user_config(username)
            stdout = (
                "deleted empty per-user config\n"
                if deleted
                else "per-user config already empty\n"
            )
        else:
            self.files.ensure_dir(path.parent, mode=0o700)
            self.files.atomic_write_private_text(path, self.render_user_config(user_config))
            stdout = f"written {path}\n"
        return CommandResult(("korctl", "user", "config", "save", username), 0, stdout, "")

    def delete_user_config(self, username: str) -> bool:
        path = self.user_config_path(username)
        if not path.exists():
            return False
        path.unlink()
        return True

    def parse_user_config_file(self, path: Path) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "dns": [],
            "nbns": [],
            "split_dns": [],
            "routes": [],
            "no_routes": [],
            "iroutes": [],
        }
        repeated = {
            "dns": "dns",
            "nbns": "nbns",
            "split-dns": "split_dns",
            "route": "routes",
            "no-route": "no_routes",
            "iroute": "iroutes",
        }
        scalar = {
            "ipv4-network": "ipv4_network",
            "ipv4-netmask": "ipv4_netmask",
            "ipv6-network": "ipv6_network",
            "ipv6-subnet-prefix": "ipv6_subnet_prefix",
            "explicit-ipv4": "explicit_ipv4",
            "explicit-ipv6": "explicit_ipv6",
            "rx-data-per-sec": "rx_data_per_sec",
            "tx-data-per-sec": "tx_data_per_sec",
            "net-priority": "net_priority",
            "keepalive": "keepalive",
            "dpd": "dpd",
            "mobile-dpd": "mobile_dpd",
            "max-same-clients": "max_same_clients",
            "stats-report-time": "stats_report_time",
            "mtu": "mtu",
            "idle-timeout": "idle_timeout",
            "mobile-idle-timeout": "mobile_idle_timeout",
            "restrict-user-to-ports": "restrict_user_to_ports",
            "session-timeout": "session_timeout",
            "hostname": "hostname",
        }
        string_fields = {
            "net_priority",
            "restrict_user_to_ports",
            "hostname",
            "ipv4_network",
            "ipv4_netmask",
            "ipv6_network",
            "explicit_ipv4",
            "explicit_ipv6",
        }
        booleans = {
            "deny-roaming": "deny_roaming",
            "no-udp": "no_udp",
            "tunnel-all-dns": "tunnel_all_dns",
            "restrict-user-to-routes": "restrict_user_to_routes",
        }
        for line in self.files.read_lines(path):
            clean = line.split("#", 1)[0].strip()
            if not clean or "=" not in clean:
                continue
            key, raw_value = [part.strip() for part in clean.split("=", 1)]
            value = raw_value.strip().strip('"')
            if key in repeated:
                parsed.setdefault(repeated[key], []).append(value)
            elif key in booleans:
                parsed[booleans[key]] = _parse_bool(value)
            elif key in scalar:
                field = scalar[key]
                parsed[field] = value if field in string_fields else _parse_int(value)
        return parsed

    def _parse_user_config(self, path: Path) -> dict[str, Any]:
        return self.parse_user_config_file(path)

    def render_user_config(self, config: UserConfig) -> str:
        lines = ["# Generated by kornode. Manual edits may be overwritten."]
        for key, values in (
            ("dns", config.dns),
            ("nbns", config.nbns),
            ("split-dns", config.split_dns),
            ("route", config.routes),
            ("no-route", config.no_routes),
            ("iroute", config.iroutes),
        ):
            lines.extend(f"{key} = {value}" for value in values)
        scalar_items: list[tuple[str, str | int | None]] = [
            ("ipv4-network", config.ipv4_network),
            ("ipv4-netmask", config.ipv4_netmask),
            ("ipv6-network", config.ipv6_network),
            ("ipv6-subnet-prefix", config.ipv6_subnet_prefix),
            ("explicit-ipv4", config.explicit_ipv4),
            ("explicit-ipv6", config.explicit_ipv6),
            ("rx-data-per-sec", config.rx_data_per_sec),
            ("tx-data-per-sec", config.tx_data_per_sec),
            ("net-priority", config.net_priority),
            ("keepalive", config.keepalive),
            ("dpd", config.dpd),
            ("mobile-dpd", config.mobile_dpd),
            ("max-same-clients", config.max_same_clients),
            ("stats-report-time", config.stats_report_time),
            ("mtu", config.mtu),
            ("idle-timeout", config.idle_timeout),
            ("mobile-idle-timeout", config.mobile_idle_timeout),
            ("restrict-user-to-ports", config.restrict_user_to_ports),
            ("session-timeout", config.session_timeout),
            ("hostname", config.hostname),
        ]
        lines.extend(f"{key} = {value}" for key, value in scalar_items if value is not None)
        for key, value in (
            ("deny-roaming", config.deny_roaming),
            ("no-udp", config.no_udp),
            ("tunnel-all-dns", config.tunnel_all_dns),
            ("restrict-user-to-routes", config.restrict_user_to_routes),
        ):
            if value is not None:
                lines.append(f"{key} = {str(value).lower()}")
        return "\n".join(lines) + "\n"

    def create_user(
        self,
        username: str,
        password: str,
        *,
        dry_run: bool = False,
    ) -> CommandResult:
        self.validate_username(username)
        self.files.ensure_dir(self.config.system.secrets_dir, mode=0o700)
        return self.runner.run(
            self._passwd_argv(username),
            input_text=f"{password}\n{password}\n",
            timeout=30,
            dry_run=dry_run,
            extra_secrets=[password],
        )

    def change_password(
        self,
        username: str,
        password: str,
        *,
        dry_run: bool = False,
    ) -> CommandResult:
        return self.create_user(username, password, dry_run=dry_run)

    def delete_user(self, username: str) -> bool:
        self.validate_username(username)
        with _PASSWD_REWRITE_LOCK:
            lines = self.files.read_lines(self.passwd_file)
            kept = [
                line
                for line in lines
                if not line.startswith(f"{username}:") and not line.startswith(f"!{username}:")
            ]
            changed = len(kept) != len(lines)
            if changed:
                self.files.atomic_write_private_text(
                    self.passwd_file,
                    "\n".join(kept) + ("\n" if kept else ""),
                )
        return changed

    def disable_user(self, username: str, *, dry_run: bool = False) -> CommandResult:
        self.validate_username(username)
        return self.runner.run(
            self._passwd_argv("-l", username),
            timeout=30,
            dry_run=dry_run,
        )

    def enable_user(self, username: str, *, dry_run: bool = False) -> CommandResult:
        self.validate_username(username)
        return self.runner.run(
            self._passwd_argv("-u", username),
            timeout=30,
            dry_run=dry_run,
        )

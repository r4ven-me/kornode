"""Inventory comes only from environment; never commit hosts or SSH material."""

from __future__ import annotations

import ipaddress
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

ROLES = ("hub", "agent-a", "agent-b", "ext")
ACK = "I_ACKNOWLEDGE_DISPOSABLE_VMS"
IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*(?:@sha256:[0-9a-f]{64})?$")


class E2EError(RuntimeError):
    """Only fixed, non-sensitive messages may cross this boundary."""


@dataclass(frozen=True, repr=False)
class Host:
    role: str
    address: str
    user: str
    port: int = 22


@dataclass(frozen=True, repr=False)
class Inventory:
    hosts: tuple[Host, ...]
    key: Path = field(repr=False)
    known_hosts: Path = field(repr=False)
    hub_address: str
    previous_hub: str | None = None
    previous_agent: str | None = None

    def host(self, role: str) -> Host:
        return next(host for host in self.hosts if host.role == role)

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, destructive: bool = True) -> Inventory:
        if destructive and env.get("E2E_ALLOW_DESTRUCTIVE") != ACK:
            raise E2EError("E2E destructive opt-in is missing")
        user = env.get("E2E_SSH_USER", "")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise E2EError("E2E_SSH_USER must be an explicit SSH account")
        try:
            port = int(env.get("E2E_SSH_PORT", "22"))
            if not 1 <= port <= 65535:
                raise ValueError()
            hosts = []
            for role in ROLES:
                address = str(
                    ipaddress.IPv4Address(env["E2E_" + role.upper().replace("-", "_") + "_HOST"])
                )
                ip = ipaddress.ip_address(address)
                if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                    raise ValueError()
                hosts.append(Host(role, address, user, port))
            if len({host.address for host in hosts}) != 4:
                raise ValueError()
            key = private_file(env["E2E_SSH_KEY_FILE"], private=True)
            known = private_file(env["E2E_KNOWN_HOSTS_FILE"], private=False)
        except (KeyError, ValueError, OSError):
            raise E2EError(
                "four distinct VM IPv4 addresses, SSH port/key and pinned known_hosts are required"
            ) from None
        advertised = env.get("E2E_HUB_ADDRESS") or hosts[0].address
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", advertised):
            raise E2EError("invalid advertised hub address")
        old_hub, old_agent = env.get("E2E_PREVIOUS_HUB_IMAGE"), env.get("E2E_PREVIOUS_AGENT_IMAGE")
        if bool(old_hub) != bool(old_agent):
            raise E2EError("both previous image digests are required for upgrade")
        for image in (old_hub, old_agent):
            if image and (not IMAGE.fullmatch(image) or "@sha256:" not in image):
                raise E2EError("previous images must be immutable sha256 references")
        return cls(tuple(hosts), key, known, advertised, old_hub, old_agent)


def private_file(value: str, *, private: bool) -> Path:
    path = Path(value)
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise ValueError()
    if private and info.st_mode & 0o077:
        raise ValueError()
    return path

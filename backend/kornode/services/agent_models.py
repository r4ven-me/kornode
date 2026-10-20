"""Management contracts shared by korctl and the authenticated admin API."""

from __future__ import annotations

import ipaddress
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from kornode.config.reserved import is_reserved_username
from kornode.net.model import NAME_PATTERN


class ManagementError(RuntimeError):
    def __init__(self, status: int, error: str, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.status, self.error, self.details = status, error, details

    def body(self) -> dict[str, Any]:
        return {"error": self.error, "message": str(self), "details": self.details}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def line_secret(value: SecretStr | None) -> SecretStr | None:
    if value is not None and any(c in value.get_secret_value() for c in ("\n", "\r", "\x00")):
        raise ValueError("line-oriented credentials cannot contain control separators")
    return value


class Transport(Model):
    transport: Literal["tcp", "auto"] = "tcp"
    dpd: int = Field(default=20, ge=5, le=3600)
    keepalive: int = Field(default=25, ge=5, le=3600)
    camouflage: SecretStr | None = None

    _line_secret = field_validator("camouflage")(line_secret)


class AgentCreate(Model):
    name: str = Field(pattern=NAME_PATTERN)
    id: int | None = Field(default=None, ge=2, le=254)
    description: str = Field(default="", max_length=1024)
    roles: list[Literal["access", "exit"]] = Field(default_factory=list, max_length=2)
    force_reuse: bool = False
    dry_run: bool = False

    @field_validator("roles")
    @classmethod
    def unique(cls, roles: list[str]) -> list[str]:
        if len(set(roles)) != len(roles):
            raise ValueError("duplicate roles")
        return roles


class AgentPatch(Model):
    description: str | None = Field(default=None, max_length=1024)
    roles: list[Literal["access", "exit"]] | None = Field(default=None, max_length=2)
    transport: Transport | None = None

    @field_validator("roles")
    @classmethod
    def unique(cls, roles: list[str] | None) -> list[str] | None:
        if roles is not None and len(set(roles)) != len(roles):
            raise ValueError("duplicate roles")
        return roles


class PrefixInput(Model):
    prefix: str
    kind: Literal["pool", "source", "lan"] = "lan"
    export: bool = True

    @field_validator("prefix")
    @classmethod
    def cidr(cls, value: str) -> str:
        return str(ipaddress.ip_network(value, strict=True))


class ExternalInput(Model):
    interface: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,15}$")
    enabled: bool = True
    server: str = Field(min_length=1, max_length=253, pattern=r"^[a-zA-Z0-9.:-]+$")
    port: int = Field(default=443, ge=1, le=65535)
    transport: Literal["tcp", "auto"] = "tcp"
    auth_type: Literal["password", "cert", "p12"] = "password"
    username: str | None = None
    password: SecretStr | None = None
    cert_pem: str | None = None
    key: SecretStr | None = None
    server_cert_pin: str | None = Field(default=None, pattern=r"^pin-sha256:")
    camouflage: SecretStr | None = None
    check_host: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.:-]*$")
    accept_server_routes: bool = False
    dns: list[str] | None = None

    _line_secret = field_validator("password", "camouflage")(line_secret)

    @model_validator(mode="after")
    def supported(self) -> Self:
        if self.auth_type == "p12":
            raise ValueError("p12 agent runtime is not implemented")
        if self.accept_server_routes:
            raise ValueError("server-pushed routes are not implemented on agents")
        if self.auth_type == "password" and not self.username:
            raise ValueError("password authentication requires a username")
        return self


class AccessUserInput(Model):
    password: SecretStr | None = None
    groups: list[str] = Field(default_factory=list, max_length=32)
    enabled: bool = True

    @field_validator("password")
    @classmethod
    def valid_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            text = value.get_secret_value()
            if not 8 <= len(text) <= 1024 or "\n" in text or "\r" in text:
                raise ValueError("password must be 8..1024 characters, without newlines")
        return value

    @field_validator("groups")
    @classmethod
    def valid_groups(cls, groups: list[str]) -> list[str]:
        import re

        if any(not re.fullmatch(NAME_PATTERN, g) or g in ("agents", "enroll") for g in groups):
            raise ValueError("invalid or reserved group")
        return sorted(set(groups))


def username(value: str) -> str:
    import re

    if not re.fullmatch(r"[a-zA-Z0-9_@.\-]{1,64}", value) or is_reserved_username(value):
        raise ManagementError(422, "invalid", "invalid or reserved username")
    return value

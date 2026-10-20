"""Egress policy model (docs/spec/02-egress-and-sources.md,
docs/spec/schemas/egress.v1.schema.json). First match wins."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,30}$"
_DOMAIN_RE = re.compile(r"^(\*\.)?([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_VIA_RE = re.compile(
    r"^(local|fabric|drop|exit:([1-9][0-9]{0,2})|upstream:([a-z][a-z0-9_-]{0,30}))$"
)

BUILTIN_CLASSES = ("clients", "host", "fabric")

Name = Annotated[str, Field(pattern=NAME_PATTERN)]


def _cidr(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Source(_Strict):
    name: Name
    interface: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,15}$")]
    cidr: str
    export: bool = True
    allow_outside_pool: bool = False
    description: Annotated[str, Field(max_length=200)] = ""

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, value: str) -> str:
        return _cidr(value)

    @field_validator("name")
    @classmethod
    def _not_builtin(cls, value: str) -> str:
        if value in BUILTIN_CLASSES:
            raise ValueError(f"source name {value!r} is reserved")
        return value


def _domains(values: list[str]) -> list[str]:
    for value in values:
        if not _DOMAIN_RE.match(value):
            raise ValueError(f"invalid domain {value!r}")
    return values


class DestSet(_Strict):
    routes: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    route_urls: tuple[str, ...] = ()
    domain_urls: tuple[str, ...] = ()

    @field_validator("routes")
    @classmethod
    def _valid_routes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_cidr(item) for item in value)

    @field_validator("domains")
    @classmethod
    def _valid_domains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_domains(list(value)))

    @field_validator("route_urls", "domain_urls")
    @classmethod
    def _valid_urls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for url in value:
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"invalid url {url!r}")
        return value


class SetRef(_Strict):
    set: Name


class NodeRef(_Strict):
    node: Annotated[int, Field(ge=1, le=254)]


class InlineDest(_Strict):
    routes: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _non_empty(self) -> InlineDest:
        if not self.routes and not self.domains:
            raise ValueError("inline destination needs routes or domains")
        return self

    @field_validator("routes")
    @classmethod
    def _valid_routes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_cidr(item) for item in value)

    @field_validator("domains")
    @classmethod
    def _valid_domains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_domains(list(value)))


To = Literal["any", "fabric"] | SetRef | NodeRef | InlineDest


@dataclass(frozen=True, slots=True)
class Via:
    kind: Literal["local", "fabric", "drop", "exit", "upstream"]
    target: str | None = None

    @classmethod
    def parse(cls, value: str) -> Via:
        match = _VIA_RE.match(value)
        if match is None:
            raise ValueError(f"invalid via {value!r}")
        if match.group(2):
            return cls("exit", match.group(2))
        if match.group(3):
            return cls("upstream", match.group(3))
        return cls(value)  # type: ignore[arg-type]

    @property
    def name(self) -> str:
        return f"{self.kind}:{self.target}" if self.target else self.kind


class Rule(_Strict):
    id: Name | None = None
    from_: Annotated[tuple[str, ...], Field(alias="from", min_length=1)]
    to: To
    via: str
    kill_switch: bool | None = None
    description: Annotated[str, Field(max_length=200)] = ""

    @field_validator("via")
    @classmethod
    def _valid_via(cls, value: str) -> str:
        Via.parse(value)
        return value

    @field_validator("from_")
    @classmethod
    def _valid_from(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate entries in from")
        for item in value:
            if item not in BUILTIN_CLASSES and not re.match(NAME_PATTERN, item):
                raise ValueError(f"invalid from entry {item!r}")
        return value

    @property
    def parsed_via(self) -> Via:
        return Via.parse(self.via)

    @property
    def effective_kill_switch(self) -> bool:
        """Default true for every via except local (spec 02)."""
        if self.kill_switch is not None:
            return self.kill_switch
        return self.parsed_via.kind != "local"


class EgressPolicy(_Strict):
    sources: tuple[Source, ...] = ()
    sets: dict[Name, DestSet] = Field(default_factory=dict)
    egress: tuple[Rule, ...] = ()

    @model_validator(mode="after")
    def _references_exist(self) -> EgressPolicy:
        names = [source.name for source in self.sources]
        if len(names) != len(set(names)):
            raise ValueError("duplicate source names")
        rule_ids = [rule.id for rule in self.egress if rule.id is not None]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("duplicate rule ids")
        known_from = set(BUILTIN_CLASSES) | set(names)
        for index, rule in enumerate(self.egress):
            for item in rule.from_:
                if item not in known_from:
                    raise ValueError(f"rule {index}: unknown source {item!r}")
            if isinstance(rule.to, SetRef) and rule.to.set not in self.sets:
                raise ValueError(f"rule {index}: unknown set {rule.to.set!r}")
        return self

"""P4-04 hub side: access listener settings, server certificate, bundle `access` (D-67)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from pydantic import ValidationError
from tests.test_agent_management import Enrollment
from tests.test_bundle_service import Env

from kornode.bundle.models import Access, AccessUser
from kornode.services.agent_models import AgentCreate, AgentPatch, ManagementError
from kornode.services.agents import AgentService
from kornode.services.certificates import CertificateService

pytestmark = pytest.mark.skipif(shutil.which("certtool") is None, reason="needs certtool")


class World:
    def __init__(self, tmp_path: Path, password_hasher: Callable[[str], str] | None = None) -> None:
        self.env = Env(tmp_path)
        CertificateService(self.env.config).init_ca()
        self.issued: list[str] = []
        self.service = AgentService(
            self.env.config,
            bundles=self.env.service,
            enrollment=Enrollment(self.env),
            sync=lambda: None,
            password_hasher=password_hasher or (lambda pw: "$6$salt$" + "h" * 86),
        )
        real = self.service.certificates

        def counting() -> Any:
            certificates = real()
            issue = certificates.issue_access_server_certificate

            def wrapped(node_id: int, hostname: str, **kwargs: Any) -> Any:
                self.issued.append(hostname)
                return issue(node_id, hostname, **kwargs)

            certificates.issue_access_server_certificate = wrapped
            return certificates

        self.service.certificates = counting  # type: ignore[method-assign]
        # An enrolled agent with role access: node 3.
        self.env.add(3, roles=["access"])
        self.env.compile(3)

    def bundle(self) -> Any:
        return self.env.check(self.env.registry.latest_bundle(3))


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    result = World(tmp_path)
    yield result
    result.env.registry.conn.close()


def test_listener_issues_a_server_certificate_once(world: World) -> None:
    shown = world.service.set_access("node3", {"hostname": "vpn.branch.example", "port": 8443})
    assert shown["configured"] and shown["port"] == 8443 and shown["role"]
    assert shown["certificate"]["pin"].startswith("pin-sha256:")
    assert world.issued == ["vpn.branch.example"]
    # Same hostname: the certificate (and so the bundle content) stays.
    world.service.set_access("node3", {"hostname": "vpn.branch.example", "port": 443})
    assert world.issued == ["vpn.branch.example"]
    world.service.set_access("node3", {"hostname": "vpn2.branch.example"})
    world.service.set_access("node3", {"hostname": "vpn2.branch.example", "reissue": True})
    assert world.issued == ["vpn.branch.example", "vpn2.branch.example", "vpn2.branch.example"]


def test_certificate_is_a_server_cert_without_ou(world: World) -> None:
    world.service.set_access("node3", {"hostname": "203.0.113.7"})
    access = world.bundle().bundle.access
    cert = x509.load_pem_x509_certificate(access.server_cert_pem.encode())
    assert not cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in usage
    assert x509.ExtendedKeyUsageOID.CLIENT_AUTH not in usage
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["203.0.113.7"]


def test_bundle_carries_hashes_and_a_sealed_key_only(world: World) -> None:
    world.service.set_access("node3", {"hostname": "vpn.branch.example"})
    world.service.set_user("node3", "alice", {"password": "alice-password", "groups": ["staff"]})
    world.service.set_user("node3", "bob", {"password": "bob-password1", "enabled": False})
    validated = world.bundle()
    access = validated.bundle.access
    assert access.auth == ("password",) and access.port == 443 and access.udp is False
    users = {user.username: user for user in access.users}
    assert users["alice"].groups == ("staff",) and users["alice"].enabled
    assert not users["bob"].enabled
    key = validated.secrets["/access/server_key"]
    assert key.startswith("-----BEGIN PRIVATE KEY-----")
    stored = world.env.registry.get_node(3).access
    assert "BEGIN PRIVATE KEY" not in json.dumps(stored)
    body = world.env.registry.latest_bundle(3).body.decode()
    assert "alice-password" not in body and "BEGIN PRIVATE KEY" not in body
    assert "key_enc" not in json.dumps(world.service.show("node3"))


def test_no_access_section_without_role_or_listener(world: World) -> None:
    assert world.bundle().bundle.access is None
    world.service.set_access("node3", {"hostname": "vpn.branch.example"})
    assert world.bundle().bundle.access is not None
    world.service.update("node3", AgentPatch(roles=[]))
    assert world.bundle().bundle.access is None
    world.service.update("node3", AgentPatch(roles=["access"]))
    world.service.set_access("node3", None)
    assert world.bundle().bundle.access is None
    assert world.service.access("node3")["configured"] is False


def test_listener_requires_the_role(world: World) -> None:
    world.service.create(AgentCreate(name="plain"))
    with pytest.raises(ManagementError) as raised:
        world.service.set_access("plain", {"hostname": "vpn.example"})
    assert raised.value.error == "role_required"
    assert world.issued == []


@pytest.mark.parametrize(
    "hostname", ["bad host", "-x.example", "a" * 60 + ".example", 'x"; cn = evil', ""]
)
def test_hostname_is_validated_before_certtool(world: World, hostname: str) -> None:
    with pytest.raises(ManagementError) as raised:
        world.service.set_access("node3", {"hostname": hostname})
    assert raised.value.status == 422
    assert world.issued == []


@pytest.mark.parametrize(
    "user",
    [
        {"username": "a:b", "enabled": True},
        {"username": "a\nb", "enabled": True},
        {"username": "alice", "pw_hash": "plain", "enabled": True},
        {"username": "alice", "pw_hash": "$6$s$h\n", "enabled": True},
        {"username": "alice", "groups": ["Staff:x"], "enabled": True},
    ],
)
def test_bundle_access_users_are_strict(user: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AccessUser.model_validate(user)


def test_bundle_access_port_range() -> None:
    with pytest.raises(ValidationError):
        Access.model_validate({"port": 0, "auth": ["password"], "ca_pem": "x", "users": []})


def test_doctor_warns_before_a_listener_certificate_expires(world: World) -> None:
    from kornode.services.doctor import DoctorService

    world.service.set_access("node3", {"hostname": "vpn.branch.example"})
    doctor = DoctorService(world.env.config)
    ok = doctor._check_access_certificates()
    assert ok.ok and "1 agent access listener" in ok.stdout
    access = dict(world.env.registry.get_node(3).access, cert_not_after="2026-11-01T00:00:00Z")
    world.env.registry.update_node(3, access=access)
    soon = doctor._check_access_certificates()
    assert not soon.ok
    assert "node3" in soon.stderr and "--reissue" in soon.stderr


def test_the_listener_certificate_is_revoked_in_the_hub_crl_when_issued(world: World) -> None:
    """Defence in depth (D-67): a hub-CA certificate without OU must not log in to the hub."""
    certificates = CertificateService(world.env.config)
    assert certificates.list_revoked_certificates() == []
    world.service.set_access("node3", {"hostname": "vpn.branch.example"})
    revoked = certificates.list_revoked_certificates()
    assert [entry["subject"] for entry in revoked] == [revoked[0]["subject"]]
    assert "vpn.branch.example" in revoked[0]["subject"]
    crl = world.env.config.cert_path("crl.pem")
    assert crl.exists() and crl.stat().st_size > 0
    # Unchanged hostname: nothing new to issue or revoke; `reissue` adds one entry.
    world.service.set_access("node3", {"hostname": "vpn.branch.example", "port": 9443})
    assert len(certificates.list_revoked_certificates()) == 1
    world.service.set_access("node3", {"hostname": "vpn.branch.example", "reissue": True})
    assert len(certificates.list_revoked_certificates()) == 2


def _policy(world: World, roles: list[str], egress: list[dict[str, Any]]) -> list[dict[str, Any]]:
    world.env.registry.update_node(3, roles=roles, policy={"egress": egress})
    world.env.compile(3)
    return [rule.model_dump(by_alias=True) for rule in world.bundle().bundle.policy.egress]


def test_clients_of_an_access_node_do_not_get_the_interlink_by_default(world: World) -> None:
    rules = _policy(world, ["access"], [])
    implicit = next(rule for rule in rules if rule["id"] == "to-interlink")
    assert "clients" not in implicit["from"] and "host" in implicit["from"]
    # Other nodes keep the old behaviour: the bundle never cuts clients from the hub.
    rules = _policy(world, [], [])
    assert "clients" in next(rule for rule in rules if rule["id"] == "to-interlink")["from"]


def test_an_explicit_client_interlink_rule_does_not_remove_the_hosts_path_to_the_hub(
    world: World,
) -> None:
    explicit = {"id": "branch-hub", "from": ["clients"], "to": "interlink", "via": "interlink"}
    rules = _policy(world, ["access"], [explicit])
    ids = [rule["id"] for rule in rules]
    assert ids == ["to-interlink", "branch-hub"]
    assert list(rules[0]["from"]) == ["host"]

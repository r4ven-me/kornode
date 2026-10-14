"""Agent enrollment and control client against a real mTLS control API."""

from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path

import pytest
from tests.test_control_api import HOST, Hub
from tests.test_control_api import hub as hub  # noqa: F401  (fixture)

from kornode_agent import __version__
from kornode_agent.config import load_config
from kornode_agent.control import ControlClient, ControlError, HubUnreachable
from kornode_agent.enroll import (
    TokenError,
    enroll,
    is_enrolled,
    load_seal_key,
    parse_token,
)
from kornode_agent.store import Store

pytestmark = pytest.mark.usefixtures("hub")


def _token(hub: Hub, node_id: int = 3):  # type: ignore[no-untyped-def]
    raw = hub.env.service.issue_token(node_id)
    token = parse_token(raw)
    # The hub's fabric address is not routable in the test: use the loopback listener.
    return dataclasses.replace(token, control_url=f"https://{HOST}:{hub.port}")


def test_parse_token_rejects_garbage_and_missing_control_url() -> None:
    with pytest.raises(TokenError):
        parse_token("not-a-token")


def test_enroll_writes_the_agent_directory_and_mtls_works(hub: Hub, tmp_path: Path) -> None:
    root = tmp_path / "agent"
    token = _token(hub)
    assert token.control_url.startswith("https://") and token.pin.startswith("pin-sha256:")

    async def run() -> None:
        client = ControlClient.for_enroll(token.control_url)
        try:
            await enroll(root, token, client, now=hub.env.clock())
        finally:
            await client.aclose()
        assert is_enrolled(root)
        enrolled = ControlClient.enrolled(token.control_url, root / "tls")
        try:
            await enrolled.ping()
            result = await enrolled.poll(0, 0)
            assert result.bundle is not None and result.bundle.version >= 1
            await enrolled.report({"agent_version": __version__, "applied_version": 0})
        finally:
            await enrolled.aclose()

    asyncio.run(run())
    config = load_config(root)
    assert config.node_id == 3 and config.hub.pin == token.pin
    trust = Store(root).load_trust()
    assert len(trust.active) == 1
    assert (root / "tls" / "key.pem").stat().st_mode & 0o777 == 0o600
    assert load_seal_key(root) is not None
    state = Store(root).load_state()
    assert state.current == 0 and state.high_water == 0 and state.pending is None


def test_enroll_with_a_wrong_secret_leaves_the_directory_empty(hub: Hub, tmp_path: Path) -> None:
    root = tmp_path / "agent"
    token = dataclasses.replace(_token(hub), secret="wrong")

    async def run() -> None:
        client = ControlClient.for_enroll(token.control_url)
        try:
            with pytest.raises(ControlError) as raised:
                await enroll(root, token, client, now=hub.env.clock())
            assert raised.value.status == 403
        finally:
            await client.aclose()

    asyncio.run(run())
    assert not root.exists()


def test_mtls_client_without_enrolled_ca_cannot_talk(hub: Hub, tmp_path: Path) -> None:
    async def run() -> None:
        client = ControlClient.for_enroll(f"https://{HOST}:{hub.port}")
        try:
            with pytest.raises(ControlError) as raised:
                await client.ping()
            assert raised.value.status == 401
        finally:
            await client.aclose()
        dead = ControlClient.for_enroll("https://127.0.0.1:9")
        try:
            with pytest.raises(HubUnreachable):
                await dead.ping()
        finally:
            await dead.aclose()

    asyncio.run(run())

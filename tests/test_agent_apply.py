"""Apply-with-confirm, rollback, boot from cache (spec 06) with a fake runtime."""

from __future__ import annotations

import base64
import copy
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from tests.test_bundle import _example, _signed

from kornode.bundle.sealing import public_bytes, seal
from kornode.bundle.signing import key_id, raw_public_bytes
from kornode.bundle.validator import Validated
from kornode_agent.apply import Applier, Convergence
from kornode_agent.store import State, Store, trust_from_enroll

UP = {"interlink": True, "upstream:office": True}


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


class FakeRuntime:
    def __init__(self) -> None:
        self.activated: list[int | None] = []
        self.error: str | None = None
        self.empty = True

    def activate(self, validated: Validated | None) -> None:
        self.activated.append(validated.bundle.version if validated else None)

    def converge(self) -> Convergence:
        return Convergence(empty=self.empty, error=self.error)


class FakeHealth:
    """checks() depends on the bundle in force: `plan[version]`; None = bootstrap."""

    def __init__(self) -> None:
        self.plan: dict[int | None, dict[str, bool]] = {None: {"interlink": True}}

    def checks(self, active: Validated | None) -> dict[str, bool]:
        version = active.bundle.version if active else None
        return dict(self.plan.get(version, UP))


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.signer = Ed25519PrivateKey.generate()
        self.seal = X25519PrivateKey.generate()
        self.store = Store(tmp_path)
        pub = raw_public_bytes(self.signer.public_key())
        self.store.save_trust(
            trust_from_enroll(
                [{"key_id": key_id(pub), "pubkey_b64": base64.b64encode(pub).decode()}]
            )
        )
        self.clock = Clock()
        self.runtime = FakeRuntime()
        self.health = FakeHealth()
        self.events: list[dict[str, Any]] = []
        self.applier = self.make()

    def make(self) -> Applier:
        return Applier(
            store=self.store,
            runtime=self.runtime,
            health=self.health,
            node_id=3,
            seal_key=self.seal,
            agent_version="2.1.0",
            clock=self.clock,
            sleep=self.clock.sleep,
            on_event=self.events.append,
        )

    def bundle(self, version: int, **mutate: Any) -> tuple[bytes, str]:
        doc = copy.deepcopy(_example())
        doc["version"] = version
        pub = public_bytes(self.seal.public_key())
        doc["tunnels"]["upstreams"][0]["password"] = seal(
            "pw", pub, 3, "/tunnels/upstreams/0/password"
        )
        doc["access"]["server_key"] = seal("pem", pub, 3, "/access/server_key")
        for key, value in mutate.items():
            doc[key] = value
        return _signed(doc, self.signer)

    def restart(self) -> Applier:
        self.applier = self.make()
        self.applier.boot()
        return self.applier


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.applier.boot()
    return w


def test_bootstrap_when_nothing_is_cached(world: World) -> None:
    assert world.applier.state == State()
    assert world.runtime.activated == [None]


def test_healthy_bundle_is_confirmed_and_cached(world: World) -> None:
    outcome = world.applier.apply_bundle(*world.bundle(5))
    assert outcome.result == "confirmed"
    state = world.store.load_state()
    assert (state.current, state.confirmed, state.high_water, state.pending) == (5, [5], 5, None)
    assert world.runtime.activated == [None, 5]


def test_unhealthy_interlink_rolls_back_and_blames_the_bundle(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    world.health.plan[6] = {"interlink": False, "upstream:office": True}

    outcome = world.applier.apply_bundle(*world.bundle(6))

    assert outcome.result == "rolled_back" and "interlink" in outcome.failed_checks
    state = world.store.load_state()
    assert (state.current, state.high_water, state.pending) == (5, 6, None)
    assert "interlink" in state.failed["6"]
    assert state.deferred is None
    assert world.runtime.activated[-2:] == [6, 5]
    assert world.clock.t >= 60  # the whole window was used


def test_interlink_down_under_previous_too_defers_instead_of_failing(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    world.health.plan[5] = {"interlink": False, "upstream:office": True}
    world.health.plan[6] = {"interlink": False, "upstream:office": True}

    world.applier.apply_bundle(*world.bundle(6))

    state = world.store.load_state()
    assert state.failed == {} and state.deferred is not None
    assert (state.deferred.version, state.deferred.attempts) == (6, 1)

    world.health.plan[6] = UP
    world.health.plan[5] = UP
    retried = world.applier.retry_deferred()
    assert retried is not None and retried.result == "confirmed"
    assert world.store.load_state().deferred is None


def test_deferred_gives_up_after_three_attempts(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    down = {"interlink": False, "upstream:office": True}
    world.health.plan[5] = down
    world.health.plan[6] = down
    world.applier.apply_bundle(*world.bundle(6))
    for _ in range(3):
        world.applier.retry_deferred()
    state = world.store.load_state()
    assert state.deferred is None and "6" in state.failed


def test_new_upstream_must_be_healthy_but_a_preexisting_outage_is_tolerated(
    world: World,
) -> None:
    world.health.plan[5] = {"interlink": True, "upstream:office": False}
    assert world.applier.apply_bundle(*world.bundle(5)).result == "rolled_back"  # new -> required

    world.health.plan[6] = UP
    assert world.applier.apply_bundle(*world.bundle(6)).result == "confirmed"

    world.health.plan[6] = {"interlink": True, "upstream:office": False}  # outage under current
    world.health.plan[7] = {"interlink": True, "upstream:office": False}
    outcome = world.applier.apply_bundle(*world.bundle(7))
    assert outcome.result == "confirmed"
    assert outcome.warnings == ("upstream:office is down (not required)",)


def test_reconciler_error_or_drift_blocks_the_confirm(world: World) -> None:
    world.runtime.error = "OSError: nft failed"
    outcome = world.applier.apply_bundle(*world.bundle(5))
    assert outcome.result == "rolled_back" and outcome.failed_checks == ("reconciler",)

    world.runtime.error = None
    world.runtime.empty = False  # never converges
    assert world.applier.apply_bundle(*world.bundle(6)).result == "rolled_back"


def test_replay_and_bad_signature_are_rejected_without_caching(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    body, _ = world.bundle(5)
    assert world.applier.apply_bundle(body, world.bundle(5)[1]).result == "invalid_bundle"
    assert world.applier.apply_bundle(*world.bundle(4)).result == "invalid_bundle"

    other = Ed25519PrivateKey.generate()
    from kornode.bundle.signing import sign

    body, _ = world.bundle(9)
    outcome = world.applier.apply_bundle(body, sign(body, other))
    assert outcome.result == "invalid_bundle" and "bad_signature" in (outcome.error or "")
    assert world.store.read_bundle(9) is None
    assert world.store.load_state().high_water == 5


def test_restart_inside_the_window_rolls_back(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    body, sig = world.bundle(6)
    world.store.write_bundle(6, body, sig)
    state = world.store.load_state()
    from kornode_agent.store import Pending

    state.pending = Pending(version=6, started_at="t", previous=5)
    state.high_water = 6
    world.store.save_state(state)

    applier = world.restart()

    assert applier.state.current == 5 and applier.state.pending is None
    assert applier.state.failed["6"] == "restart during confirm"
    assert applier.state.high_water == 6
    assert world.runtime.activated[-1] == 5


def test_boot_from_cache_skips_a_bundle_that_no_longer_verifies(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    world.applier.apply_bundle(*world.bundle(6))
    (world.store.bundles / "6.json").write_bytes(b"tampered")

    applier = world.restart()

    assert applier.state.current == 5
    assert any(e["type"] == "skipped" and e["version"] == 6 for e in world.events)

    for path in world.store.bundles.glob("*"):
        path.unlink()
    assert world.restart().state.current == 0  # bootstrap


def test_cache_keeps_three_confirmed_versions(world: World) -> None:
    for version in (1, 2, 3, 4, 5):
        assert world.applier.apply_bundle(*world.bundle(version)).result == "confirmed"
    assert world.store.cached_versions() == [5, 4, 3]
    assert world.store.load_state().confirmed == [5, 4, 3]


def test_local_rollback_uses_the_window_and_keeps_high_water(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    world.applier.apply_bundle(*world.bundle(6))

    outcome = world.applier.rollback_to(5)

    assert outcome.result == "confirmed"
    state = world.store.load_state()
    assert (state.current, state.high_water) == (5, 6)
    assert world.applier.rollback_to(99).result == "skipped"


def test_a_crash_while_activating_rolls_back_instead_of_wedging(world: World) -> None:
    world.applier.apply_bundle(*world.bundle(5))
    real = world.runtime.activate

    def boom(validated: Validated | None) -> None:
        if validated is not None and validated.bundle.version == 6:
            raise OSError("disk full")
        real(validated)

    world.runtime.activate = boom  # type: ignore[method-assign]
    outcome = world.applier.apply_bundle(*world.bundle(6))

    assert outcome.result == "rolled_back" and "disk full" in (outcome.error or "")
    state = world.store.load_state()
    assert state.pending is None and state.current == 5

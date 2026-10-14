"""Apply-with-confirm state machine (spec 06 "Apply-with-confirm").

Synchronous on purpose: the run loop calls it from a worker thread, and the
tests drive it with a fake runtime, health and clock. Every step is a complete
desired state handed to the runtime, so applying and rolling back are the same
operation with different input.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kornode.bundle.errors import BundleError
from kornode.bundle.validator import Validated, validate
from kornode_agent.store import Deferred, LastApply, Pending, State, Store

DEFAULT_CONFIRM_WINDOW = 60
CHECK_INTERVAL = 3.0
BLAME_SECONDS = 30.0
MAX_DEFER_ATTEMPTS = 3

Result = Literal["confirmed", "rolled_back", "invalid_bundle", "skipped"]


@dataclass(frozen=True)
class Convergence:
    """One reconciler pass: `run_once` never raises, so its outcome is the
    recorded `last_error` plus whether the plan was empty (no drift)."""

    empty: bool
    error: str | None


class Runtime(Protocol):
    def activate(self, validated: Validated | None) -> None:
        """Switch the provider to `validated` (None = bootstrap) and make the
        tunnels match. Does not converge."""

    def converge(self) -> Convergence: ...


class Health(Protocol):
    def checks(self, active: Validated | None) -> dict[str, bool]:
        """`fabric` and `upstream:<name>` checks for the bundle in force."""


@dataclass(frozen=True)
class Outcome:
    result: Result
    version: int
    error: str | None = None
    failed_checks: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass
class Applier:
    store: Store
    runtime: Runtime
    health: Health
    node_id: int
    seal_key: X25519PrivateKey
    agent_version: str
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    on_event: Callable[[dict[str, Any]], None] = lambda event: None
    state: State = field(default_factory=State)
    active: Validated | None = None

    # ------------------------------------------------------------------ boot

    def boot(self) -> State:
        """Lifecycle "start": recover from a crash inside a confirm window,
        then bring up the newest cached bundle that still verifies."""
        state = self.store.load_state()
        if state.pending is not None:
            pending = state.pending
            state.failed[str(pending.version)] = "restart during confirm"
            state.current = pending.previous
            state.pending = None
            state.last_apply = LastApply(
                version=pending.version,
                result="rolled_back",
                at=self._stamp(),
                error="restart during confirm",
            )
            self.on_event(
                {
                    "type": "rolled_back",
                    "version": pending.version,
                    "error": "restart during confirm",
                }
            )
        self.state = state
        candidates = [state.current] if state.current else []
        candidates += [v for v in state.confirmed if v not in candidates]
        self.active = None
        for version in candidates:
            validated = self._load_cached(version)
            if validated is not None:
                self.active = validated
                state.current = version
                break
        else:
            state.current = 0
        self.runtime.activate(self.active)
        self.runtime.converge()
        if self.active is not None:
            self._adopt_next_key(self.active)
        self.store.save_state(state)
        return state

    def _load_cached(self, version: int) -> Validated | None:
        cached = self.store.read_bundle(version)
        if cached is None:
            self.on_event({"type": "skipped", "version": version, "error": "not cached"})
            return None
        try:
            return self._verify(cached.body, cached.signature, version=version)
        except BundleError as exc:
            self.on_event({"type": "skipped", "version": version, "error": f"{exc.code}: {exc}"})
            return None

    def _verify(self, body: bytes, signature: str, *, version: int | None) -> Validated:
        """Spec 05 validator. A new bundle (version None) trusts `active` keys
        and must be above high-water; a cached one also trusts retired keys
        up to their `max_version` and skips the replay check."""
        trust = self.store.load_trust()
        return validate(
            body,
            signature,
            trusted=trust.keys_for(version),
            high_water_version=self.state.high_water,
            agent_version=self.agent_version,
            expected_node_id=self.node_id,
            seal_private_key=self.seal_key,
            revalidate=version is not None,
        )

    def _adopt_next_key(self, validated: Validated) -> None:
        # Idempotent: a crash between a confirm and the trust write must not
        # lose the announced key (spec 06 "Trust store").
        next_key = validated.bundle.next_signing_pubkey
        if next_key:
            trust = self.store.load_trust()
            before = len(trust.active)
            trust.add_active(next_key, pending_rotation=True)
            if len(trust.active) != before:
                self.store.save_trust(trust)

    # ----------------------------------------------------------------- apply

    def apply_bundle(self, body: bytes, signature: str) -> Outcome:
        """A new bundle from the hub: verify, stage, apply, confirm or roll back."""
        try:
            validated = self._verify(body, signature, version=None)
        except BundleError as exc:
            self.on_event({"type": "invalid_bundle", "code": exc.code, "error": str(exc)})
            return Outcome("invalid_bundle", 0, error=f"{exc.code}: {exc}")
        version = validated.bundle.version
        self.store.write_bundle(version, body, signature)
        self.state.high_water = version
        return self._switch(validated, raise_high_water=True)

    def rollback_to(self, version: int) -> Outcome:
        """Local emergency rollback to a cached confirmed version (same window)."""
        if version not in self.state.confirmed:
            return Outcome("skipped", version, error="not a confirmed version")
        if version == self.state.current:
            return Outcome("skipped", version, error="already current")
        validated = self._load_cached(version)
        if validated is None:
            return Outcome("invalid_bundle", version, error="cached bundle does not verify")
        return self._switch(validated, raise_high_water=False)

    def retry_deferred(self) -> Outcome | None:
        """Re-apply a version whose rollback was blamed on the hub path."""
        deferred = self.state.deferred
        if deferred is None or self.state.pending is not None:
            return None
        validated = self._load_cached(deferred.version)
        if validated is None:
            self.state.failed[str(deferred.version)] = "deferred bundle lost"
            self.state.deferred = None
            self.store.save_state(self.state)
            return Outcome("invalid_bundle", deferred.version, error="deferred bundle lost")
        return self._switch(validated, raise_high_water=False, retry=True)

    # ----------------------------------------------------------- core switch

    def _switch(self, target: Validated, *, raise_high_water: bool, retry: bool = False) -> Outcome:
        state = self.state
        version = target.bundle.version
        previous = self.active
        baseline = self.health.checks(previous)  # taken under `current`
        state.pending = Pending(version=version, started_at=self._stamp(), previous=state.current)
        self.store.save_state(state)

        self.runtime.activate(target)
        convergence = self.runtime.converge()
        window = (
            target.bundle.settings.confirm_window_seconds
            if target.bundle.settings and target.bundle.settings.confirm_window_seconds
            else DEFAULT_CONFIRM_WINDOW
        )
        required = self._required(target, previous, baseline)
        passed, last = self._window(target, required, convergence, window)
        failed = tuple(sorted(required - passed))
        warnings = self._warnings(target, required, last)
        if not failed:
            return self._confirm(target, warnings)
        return self._rollback(
            target, previous, failed, warnings, raise_high_water=raise_high_water, retry=retry
        )

    def _required(
        self, target: Validated, previous: Validated | None, baseline: dict[str, bool]
    ) -> set[str]:
        required = {"fabric", "reconciler"}
        old = _upstream_signatures(previous) if previous else {}
        new_sigs = _upstream_signatures(target)
        by_name = {u.name: u for u in target.bundle.tunnels.upstreams if u.enabled}
        for name in _referenced_upstreams(target):
            check = f"upstream:{name}"
            upstream = by_name.get(name)
            if upstream is None:
                continue
            new = name not in old or old[name] != new_sigs[name]
            if new or baseline.get(check, False):
                required.add(check)
        return required

    def _window(
        self, target: Validated, required: set[str], first: Convergence, window: int
    ) -> tuple[set[str], dict[str, bool]]:
        deadline = self.clock() + window
        passed: set[str] = set()
        seen_clean = first.error is None
        results: dict[str, bool] = {}
        while True:
            results = self.health.checks(target)
            passed |= {name for name, ok in results.items() if ok and name in required}
            convergence = self.runtime.converge()
            if convergence.error is None:
                if seen_clean and convergence.empty:
                    passed.add("reconciler")
                seen_clean = True
            else:
                seen_clean = False
            if required <= passed or self.clock() >= deadline:
                return passed, results
            self.sleep(CHECK_INTERVAL)

    def _warnings(
        self, target: Validated, required: set[str], last: dict[str, bool]
    ) -> tuple[str, ...]:
        return tuple(
            f"upstream:{name} is down (not required)"
            for name in sorted(_referenced_upstreams(target))
            if f"upstream:{name}" not in required and not last.get(f"upstream:{name}", False)
        )

    def _confirm(self, target: Validated, warnings: tuple[str, ...]) -> Outcome:
        state = self.state
        version = target.bundle.version
        trust = self.store.load_trust()
        trust.confirmed(target.key_id, version, target.bundle.next_signing_pubkey)
        self.store.save_trust(trust)
        state.current = version
        state.confirmed = [version] + [v for v in state.confirmed if v != version]
        state.confirmed = state.confirmed[:3]
        state.pending = None
        if state.deferred is not None and state.deferred.version <= version:
            state.deferred = None
        state.last_apply = LastApply(version=version, result="confirmed", at=self._stamp())
        self.active = target
        self.store.save_state(state)
        self.store.prune(state)
        self.on_event({"type": "confirmed", "version": version, "warnings": list(warnings)})
        return Outcome("confirmed", version, warnings=warnings)

    def _rollback(
        self,
        target: Validated,
        previous: Validated | None,
        failed: tuple[str, ...],
        warnings: tuple[str, ...],
        *,
        raise_high_water: bool,
        retry: bool,
    ) -> Outcome:
        state = self.state
        version = target.bundle.version
        error = "health: " + ", ".join(failed)
        self.runtime.activate(previous)
        self.runtime.converge()
        state.pending = None
        state.last_apply = LastApply(
            version=version, result="rolled_back", at=self._stamp(), error=error
        )
        self.store.save_state(state)
        self.on_event({"type": "rolled_back", "version": version, "failed_checks": list(failed)})
        if raise_high_water or retry:
            self._blame(version, previous, error, retry=retry)
        return Outcome("rolled_back", version, error=error, failed_checks=failed, warnings=warnings)

    def _blame(self, version: int, previous: Validated | None, error: str, *, retry: bool) -> None:
        """Fabric healthy under `previous` -> the bundle broke it (failed);
        still down -> the hub or the path is down (deferred, bounded)."""
        state = self.state
        deadline = self.clock() + BLAME_SECONDS
        healthy = False
        while True:
            if self.health.checks(previous).get("fabric", False):
                healthy = True
                break
            if self.clock() >= deadline:
                break
            self.sleep(CHECK_INTERVAL)
        if healthy:
            state.failed[str(version)] = error
            state.deferred = None
        else:
            attempts = 1
            if state.deferred is not None and state.deferred.version == version:
                attempts = state.deferred.attempts + (1 if retry else 0)
            if attempts > MAX_DEFER_ATTEMPTS:
                state.failed[str(version)] = f"{error} (hub unreachable, gave up)"
                state.deferred = None
            else:
                state.deferred = Deferred(version=version, attempts=attempts)
        self.store.save_state(state)

    def _stamp(self) -> str:
        return self.now().isoformat(timespec="seconds")


def _upstream_signatures(validated: Validated) -> dict[str, Any]:
    """Upstream parameters comparable across bundles: sealed values are fresh
    ciphertext every time, so they are compared by their plaintext."""
    result: dict[str, Any] = {}
    for index, upstream in enumerate(validated.bundle.tunnels.upstreams):
        plain = upstream.model_dump(exclude={"password", "key", "camouflage"})
        prefix = f"/tunnels/upstreams/{index}/"
        secrets = {k: v for k, v in validated.secrets.items() if k.startswith(prefix)}
        result[upstream.name] = (plain, {k.removeprefix(prefix): v for k, v in secrets.items()})
    return result


def _referenced_upstreams(validated: Validated) -> set[str]:
    return {
        rule.parsed_via.target or ""
        for rule in validated.bundle.policy.egress
        if rule.parsed_via.kind == "upstream"
    } - {""}


__all__ = ["Applier", "Convergence", "Health", "Outcome", "Runtime"]

from __future__ import annotations

import os
import signal
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from types import FrameType
from typing import Any, Self

from kornode.services.command import CommandResult, CommandRunner

SignalHandler = Callable[[int, FrameType | None], Any] | int | None


@dataclass(frozen=True)
class Namespace:
    name: str
    full_name: str
    runner: CommandRunner

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        return self.runner.run(["ip", "netns", "exec", self.full_name, *argv], **kwargs)


class Lab:
    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner()
        self.prefix = uuid.uuid4().hex[:8]
        self.namespaces: list[Namespace] = []
        self.veths: list[tuple[str, str]] = []
        self._veth_index = 0
        self._closed = False
        self._signal_installed = True
        self._previous_sigint_handler: SignalHandler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_sigint)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        self.teardown()

    def add_namespace(self, name: str) -> Namespace:
        full_name = self._prefixed(name)
        self.runner.run(["ip", "netns", "add", full_name])
        namespace = Namespace(name=name, full_name=full_name, runner=self.runner)
        self.namespaces.append(namespace)
        namespace.run(["ip", "link", "set", "lo", "up"])
        return namespace

    def add_veth(
        self,
        ns_a: Namespace,
        ns_b: Namespace,
        *,
        addr_a: str | None = None,
        addr_b: str | None = None,
    ) -> None:
        iface_a, iface_b = self._next_veth_names()
        self.runner.run(["ip", "link", "add", iface_a, "type", "veth", "peer", "name", iface_b])
        self.veths.append((iface_a, iface_b))
        try:
            self.runner.run(["ip", "link", "set", iface_a, "netns", ns_a.full_name])
            self.runner.run(["ip", "link", "set", iface_b, "netns", ns_b.full_name])
            if addr_a is not None:
                ns_a.run(["ip", "addr", "add", addr_a, "dev", iface_a])
            if addr_b is not None:
                ns_b.run(["ip", "addr", "add", addr_b, "dev", iface_b])
            ns_a.run(["ip", "link", "set", iface_a, "up"])
            ns_b.run(["ip", "link", "set", iface_b, "up"])
        except BaseException:
            self.runner.run(["ip", "link", "del", iface_a], check=False)
            self.runner.run(["ip", "link", "del", iface_b], check=False)
            raise

    def teardown(self) -> None:
        if not self._closed:
            for namespace in reversed(self.namespaces):
                self.runner.run(["ip", "netns", "del", namespace.full_name], check=False)
            self._closed = True
        self._restore_sigint_handler()

    def _prefixed(self, name: str) -> str:
        return f"{self.prefix}-{name}"

    def _next_veth_names(self) -> tuple[str, str]:
        self._veth_index += 1
        base = f"kn{self.prefix[:6]}{self._veth_index:x}"
        return f"{base}a", f"{base}b"

    def _handle_sigint(self, signum: int, frame: FrameType | None) -> None:
        self.teardown()
        signal.signal(signum, self._previous_sigint_handler)
        os.kill(os.getpid(), signum)

    def _restore_sigint_handler(self) -> None:
        if self._signal_installed:
            signal.signal(signal.SIGINT, self._previous_sigint_handler)
            self._signal_installed = False


def namespace_names(result: CommandResult) -> set[str]:
    return {line.split()[0] for line in result.stdout.splitlines() if line.strip()}

from __future__ import annotations

from types import TracebackType
from typing import Any

import pytest

from kornode.net import kernel as kernel_module
from kornode.net.diff import (
    AddRule,
    DelRoute,
    DelRule,
    NftLoad,
    Op,
    Plan,
    ReplaceRoute,
    SetSysctl,
    UpdateElements,
)
from kornode.net.errors import ApplyError
from kornode.net.kernel import Kernel
from kornode.net.state import IpRule, NftRuleset, Route, Sysctl

SYSCTL = SetSysctl(Sysctl("net.ipv4.ip_forward", "1"))
ROUTE = ReplaceRoute(Route(table=12001, dst="default", type="unreachable", metric=4096))
RULE = AddRule(IpRule(priority=101, table=12001, fwmark=0x0C000100, fwmask=0xFFFFFF00))
STALE_RULE = DelRule(IpRule(priority=102, table=12002, fwmark=0x0C000200, fwmask=0xFFFFFF00))
STALE_ROUTE = DelRoute(Route(table=12002, dst="default", type="unreachable", metric=4096))
NFT = NftLoad(NftRuleset("table inet kornode {\n}\n"))


class _NoNetlink:
    def __enter__(self) -> _NoNetlink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


class RecordingKernel(Kernel):
    def __init__(self, failing: set[Op]) -> None:
        super().__init__()
        self.failing = failing
        self.applied: list[Op] = []

    def _apply_one(self, ipr: Any, op: Op) -> None:
        if op in self.failing:
            raise OSError(19, "No such device")
        self.applied.append(op)

    def _apply_nft(self, batch: list[NftLoad | UpdateElements]) -> None:
        self.applied.extend(batch)


@pytest.fixture(autouse=True)
def no_netlink(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kernel_module, "IPRoute", _NoNetlink)


def test_clean_plan_applies_every_op_in_order() -> None:
    plan = Plan((SYSCTL, ROUTE, RULE, STALE_RULE, NFT, STALE_ROUTE))
    kernel = RecordingKernel(failing=set())

    kernel.apply(plan)

    assert kernel.applied == list(plan.ops)


def test_failed_sysctl_still_installs_routes_rules_and_the_kill_switch() -> None:
    kernel = RecordingKernel(failing={SYSCTL})

    with pytest.raises(ApplyError, match="No such device"):
        kernel.apply(Plan((SYSCTL, ROUTE, RULE, NFT)))

    assert kernel.applied == [ROUTE, RULE, NFT]


def test_deletions_are_skipped_after_a_failure() -> None:
    # A new rule failed: the old one stays rather than leaving its marks
    # without any rule while the pass is half-applied.
    kernel = RecordingKernel(failing={RULE})

    with pytest.raises(ApplyError):
        kernel.apply(Plan((ROUTE, RULE, STALE_RULE, NFT, STALE_ROUTE)))

    assert kernel.applied == [ROUTE, NFT]


def test_all_failures_are_reported_together() -> None:
    kernel = RecordingKernel(failing={SYSCTL, ROUTE})

    with pytest.raises(ApplyError) as exc:
        kernel.apply(Plan((SYSCTL, ROUTE, RULE)))

    assert str(exc.value).count("No such device") == 2
    assert kernel.applied == [RULE]

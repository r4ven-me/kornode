"""The only code that changes kernel networking state.

Reads an ActualState (pyroute2 netlink for rules/routes, /proc/sys for
sysctls, `nft -j` for kornode's own tables) and applies a Plan: sysctls via
/proc, rules/routes via netlink, and every nft change of a plan as one
`nft -f` transaction. Runs in whatever network namespace the process is in.

pyroute2 traps verified against 0.9.6 on the netlab VM:
- the rule keyword is `suppress_prefixlen`; `suppress_prefixlength` is
  silently ignored and yields a plain `lookup main` rule (would send all
  traffic past every tunnel);
- FRA_SUPPRESS_PREFIXLEN reads back as 0xffffffff when unset;
- tables > 255 are only in FRA_TABLE (the header says 252);
- non-unicast IPv6 routes read back with RTA_OIF = lo;
- `get_routes(table=0)` returns nothing; omit `table` to list all tables;
- `route("del")` needs scope=255 (RT_SCOPE_NOWHERE) or device routes never match;
- `route("get")` takes the mark as `mark=`; `fwmark=` is silently ignored.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pyroute2 import IPRoute  # type: ignore[import-untyped]
from pyroute2.netlink.exceptions import NetlinkError  # type: ignore[import-untyped]

from kornode.net.diff import (
    AddRule,
    DeleteForeignRule,
    DelRoute,
    DelRule,
    InsertForeignRule,
    NftLoad,
    Op,
    Plan,
    ReplaceRoute,
    SetSysctl,
    UpdateElements,
)
from kornode.net.errors import ApplyError
from kornode.net.state import (
    COMPAT_COMMENT,
    OWNED_NFT_TABLES,
    TABLE_ID_MAX,
    TABLE_ID_MIN,
    ActualState,
    Family,
    ForeignNftRule,
    IpRule,
    NftElements,
    Route,
    RouteType,
    Sysctl,
    TableRef,
)

SCHEMA_COMMENT_PREFIX = "kornode-schema:"
_NAMED_TABLES: dict[int, TableRef] = {253: "default", 254: "main", 255: "local"}
_TABLE_IDS = {name: number for number, name in _NAMED_TABLES.items()}
_ROUTE_TYPES: dict[int, RouteType] = {1: "unicast", 6: "blackhole", 7: "unreachable", 9: "throw"}
_TYPE_IDS = {name: number for number, name in _ROUTE_TYPES.items()}
_UNSET = 0xFFFFFFFF
_AF: dict[Family, int] = {4: socket.AF_INET, 6: socket.AF_INET6}


def _family(af: int) -> Family:
    return 4 if af == socket.AF_INET else 6


def _sysctl_path(proc_sys: Path, key: str) -> Path:
    return proc_sys.joinpath(*key.split("."))


# Skipped once an op in the same pass failed.
DESTRUCTIVE_OPS = (DelRule, DelRoute, DeleteForeignRule)


class Kernel:
    def __init__(self, *, nft: str = "nft", proc_sys: Path = Path("/proc/sys")) -> None:
        self.nft = nft
        self.proc_sys = proc_sys

    # -- read ---------------------------------------------------------------

    def read(
        self,
        sysctl_keys: Iterable[str] = (),
        foreign_chains: Iterable[tuple[str, str, str]] = (),
    ) -> ActualState:
        with IPRoute() as ipr:
            links = {link["index"]: link.get_attr("IFLA_IFNAME") for link in ipr.get_links()}
            rules = frozenset(
                rule
                for af in _AF.values()
                for message in ipr.get_rules(family=af)
                if (rule := _parse_rule(message)) is not None
            )
            routes = frozenset(
                route
                for af in _AF.values()
                # No `table=` argument: that lists every table. `table=0`
                # silently matches nothing (verified on pyroute2 0.9.6).
                for message in ipr.get_routes(family=af)
                if (route := _parse_route(message, links)) is not None
            )
        schema_hash, elements = self._read_nft()
        chains, foreign = self._read_foreign(foreign_chains)
        return ActualState(
            sysctls=frozenset(self._read_sysctls(sysctl_keys)),
            rules=rules,
            routes=routes,
            nft_schema_hash=schema_hash,
            elements=elements,
            foreign_rules=foreign,
            foreign_chains=chains,
        )

    def _list_chain(self, family: str, table: str, chain: str) -> list[tuple[str, str]] | None:
        """(rule text, handle) of every rule in a chain, None if absent."""
        result = subprocess.run(
            [self.nft, "-a", "list", "chain", family, table, chain],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        rules = []
        for line in result.stdout.splitlines():
            text, _, handle = line.strip().rpartition("# handle ")
            if handle.isdigit() and text and not text.startswith(("chain ", "type ")):
                rules.append((text.strip(), handle))
        return rules

    def _read_foreign(
        self, chains: Iterable[tuple[str, str, str]]
    ) -> tuple[frozenset[tuple[str, str, str]], frozenset[ForeignNftRule]]:
        present: set[tuple[str, str, str]] = set()
        found: set[ForeignNftRule] = set()
        tag = f'comment "{COMPAT_COMMENT}"'
        for family, table, chain in set(chains):
            rules = self._list_chain(family, table, chain)
            if rules is None:
                continue
            present.add((family, table, chain))
            for text, _ in rules:
                if text.endswith(tag):
                    expr = text[: -len(tag)].strip()
                    found.add(ForeignNftRule(family, table, chain, expr))
        return frozenset(present), frozenset(found)

    def _read_sysctls(self, keys: Iterable[str]) -> list[Sysctl]:
        found = []
        for key in keys:
            try:
                value = _sysctl_path(self.proc_sys, key).read_text(encoding="utf-8").strip()
            except OSError:
                continue  # e.g. a per-interface key for an interface not there yet
            found.append(Sysctl(key, value))
        return found

    def _read_nft(self) -> tuple[str | None, frozenset[NftElements]]:
        """Schema hash from the comment on `inet kornode` (written at load
        time), plus the elements of every set in kornode's tables."""
        schema_hash: str | None = None
        elements: set[NftElements] = set()
        for family, table in sorted(OWNED_NFT_TABLES):
            result = subprocess.run(
                [self.nft, "-j", "list", "table", family, table],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                if (family, table) == ("inet", "kornode"):
                    return None, frozenset()
                continue
            for item in json.loads(result.stdout).get("nftables", []):
                if "table" in item and (family, table) == ("inet", "kornode"):
                    comment = item["table"].get("comment", "")
                    if comment.startswith(SCHEMA_COMMENT_PREFIX):
                        schema_hash = comment[len(SCHEMA_COMMENT_PREFIX) :]
                if "set" in item:
                    data = item["set"]
                    members = frozenset(
                        text for elem in data.get("elem", []) for text in _element_texts(elem)
                    )
                    elements.add(NftElements(family, table, data["name"], members))
        return schema_hash, frozenset(elements)

    def route_get(self, dst: str, mark: int | None, src: str | None = None) -> str | None:
        """Output device the kernel picks for `dst` with `mark` (like `ip
        route get <dst> mark <mark>`), or None if it is unreachable/rejected.
        The pyroute2 keyword is `mark`; `fwmark` is silently ignored and would
        report the uplink route instead (verified on 0.9.6)."""
        args: dict[str, Any] = {"dst": dst}
        if mark is not None:
            args["mark"] = mark
        if src is not None:
            args["src"] = src
        with IPRoute() as ipr:
            try:
                messages = ipr.route("get", **args)
            except NetlinkError:
                return None
            if not messages or messages[0]["type"] != 1:
                return None
            oif = messages[0].get_attr("RTA_OIF")
            names = ipr.get_links(oif) if oif else []
            return str(names[0].get_attr("IFLA_IFNAME")) if names else None

    # -- apply --------------------------------------------------------------

    def apply(self, plan: Plan) -> None:
        """Apply `plan` in order. Consecutive nft ops go out as one
        transaction. A failed op does not stop the ops that only add state
        (sysctls, routes, rules, the nft ruleset with the kill-switch): one
        bad sysctl or a tunnel vanishing mid-pass must not leave the node
        without its fail-closed rules. Deletions after a failure are skipped,
        so nothing is torn down on top of a half-applied pass. All failures
        are raised together as one ApplyError at the end; the next pass diffs
        from what is really there."""
        ops = list(plan.ops)
        errors: list[str] = []
        index = 0
        with IPRoute() as ipr:
            while index < len(ops):
                op = ops[index]
                if errors and isinstance(op, DESTRUCTIVE_OPS):
                    index += 1
                    continue
                try:
                    if isinstance(op, (InsertForeignRule, DeleteForeignRule)):
                        index += 1
                        self._apply_foreign(op)
                    elif isinstance(op, (NftLoad, UpdateElements)):
                        batch: list[NftLoad | UpdateElements] = []
                        while index < len(ops) and isinstance(
                            ops[index], (NftLoad, UpdateElements)
                        ):
                            batch.append(ops[index])  # type: ignore[arg-type]
                            index += 1
                        self._apply_nft(batch)
                    else:
                        index += 1
                        self._apply_one(ipr, op)
                except ApplyError as exc:
                    errors.append(str(exc))
                except (NetlinkError, OSError) as exc:
                    errors.append(f"{op}: {exc}")
        if errors:
            raise ApplyError("; ".join(errors))

    def _apply_one(self, ipr: Any, op: Op) -> None:
        if isinstance(op, SetSysctl):
            _sysctl_path(self.proc_sys, op.sysctl.key).write_text(
                op.sysctl.value + "\n", encoding="utf-8"
            )
        elif isinstance(op, AddRule):
            ipr.rule("add", **_rule_args(op.rule))
        elif isinstance(op, DelRule):
            ipr.rule("del", **_rule_args(op.rule))
        elif isinstance(op, ReplaceRoute):
            ipr.route("replace", **_route_args(op.route, ipr))
        elif isinstance(op, DelRoute):
            ipr.route("del", **_route_args(op.route, ipr, for_delete=True))

    def _apply_foreign(self, op: InsertForeignRule | DeleteForeignRule) -> None:
        rule = op.rule
        if isinstance(op, InsertForeignRule):
            argv = [
                self.nft, "insert", "rule", rule.family, rule.table, rule.chain,
                *rule.expr.split(), "comment", f'"{COMPAT_COMMENT}"',
            ]
        else:
            tagged = f'{rule.expr} comment "{COMPAT_COMMENT}"'
            handles = [
                handle
                for text, handle in self._list_chain(rule.family, rule.table, rule.chain) or []
                if text == tagged
            ]
            if not handles:
                return
            argv = [
                self.nft, "delete", "rule", rule.family, rule.table, rule.chain,
                "handle", handles[0],
            ]
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise ApplyError(f"{op}: {result.stderr.strip()}")

    def _apply_nft(self, batch: list[NftLoad | UpdateElements]) -> None:
        lines: list[str] = []
        for op in batch:
            if isinstance(op, NftLoad):
                for family, table in sorted(OWNED_NFT_TABLES):
                    # `add` first so `delete` never fails on a fresh kernel.
                    lines += [f"table {family} {table}", f"delete table {family} {table}"]
                lines.append(_with_schema_comment(op.ruleset.script, op.ruleset.schema_hash))
            else:
                lines.append(f"flush set {op.family} {op.table} {op.set_name}")
                if op.target:
                    members = ", ".join(sorted(op.target))
                    lines.append(
                        f"add element {op.family} {op.table} {op.set_name} {{ {members} }}"
                    )
        script = "\n".join(lines) + "\n"
        result = subprocess.run(
            [self.nft, "-f", "-"], input=script, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise ApplyError(f"nft transaction failed: {result.stderr.strip()}")


def _with_schema_comment(script: str, schema_hash: str) -> str:
    head = "table inet kornode {"
    if head not in script:
        raise ApplyError("nft script has no `table inet kornode` block")
    return script.replace(head, f'{head}\n  comment "{SCHEMA_COMMENT_PREFIX}{schema_hash}"', 1)


def _element_texts(elem: Any) -> list[str]:
    if isinstance(elem, str):
        return [elem]
    if "prefix" in elem:
        return [f"{elem['prefix']['addr']}/{elem['prefix']['len']}"]
    if "range" in elem:
        start, end = (ipaddress.ip_address(value) for value in elem["range"])
        return [
            str(net)
            for net in ipaddress.summarize_address_range(start, end)
        ]
    if "elem" in elem:
        return _element_texts(elem["elem"]["val"])
    raise ApplyError(f"unexpected nft element {elem!r}")


def _parse_rule(message: Any) -> IpRule | None:
    attrs = dict(message["attrs"])
    if message["action"] != 1:  # FR_ACT_TO_TBL only; nothing kornode makes is else
        return None
    family = _family(message["family"])
    table_id = attrs.get("FRA_TABLE", message["table"])
    table: TableRef = _NAMED_TABLES.get(table_id, table_id)
    suppress = attrs.get("FRA_SUPPRESS_PREFIXLEN", _UNSET)
    dst = attrs.get("FRA_DST")
    return IpRule(
        priority=attrs.get("FRA_PRIORITY", 0),
        table=table,
        family=family,
        fwmark=attrs.get("FRA_FWMARK"),
        fwmask=attrs.get("FRA_FWMASK") if "FRA_FWMARK" in attrs else None,
        to=f"{dst}/{message['dst_len']}" if dst else None,
        suppress_prefixlength=None if suppress == _UNSET else suppress,
    )


def _parse_route(message: Any, links: dict[int, str]) -> Route | None:
    attrs = dict(message["attrs"])
    table = attrs.get("RTA_TABLE", message["table"])
    if not TABLE_ID_MIN <= table <= TABLE_ID_MAX:
        return None
    route_type = _ROUTE_TYPES.get(message["type"])
    if route_type is None:
        return None
    family = _family(message["family"])
    dst = attrs.get("RTA_DST")
    unicast = route_type == "unicast"
    return Route(
        table=table,
        dst=f"{dst}/{message['dst_len']}" if dst else "default",
        type=route_type,
        dev=links.get(attrs["RTA_OIF"]) if unicast and "RTA_OIF" in attrs else None,
        gateway=attrs.get("RTA_GATEWAY") if unicast else None,
        metric=attrs.get("RTA_PRIORITY", 0),
        family=family,
    )


def _rule_args(rule: IpRule) -> dict[str, Any]:
    table = rule.table if isinstance(rule.table, int) else _TABLE_IDS[rule.table]
    args: dict[str, Any] = {
        "family": _AF[rule.family],
        "priority": rule.priority,
        "table": table,
    }
    if rule.fwmark is not None:
        args["fwmark"] = rule.fwmark
        if rule.fwmask is not None:
            args["fwmask"] = rule.fwmask
    if rule.to is not None:
        network = ipaddress.ip_network(rule.to)
        args["dst"] = str(network.network_address)
        args["dst_len"] = network.prefixlen
    if rule.suppress_prefixlength is not None:
        args["suppress_prefixlen"] = rule.suppress_prefixlength  # NOT ..._prefixlength
    return args


def _route_args(route: Route, ipr: Any, *, for_delete: bool = False) -> dict[str, Any]:
    args: dict[str, Any] = {
        "family": _AF[route.family],
        "table": route.table,
        "type": _TYPE_IDS[route.type],
        "priority": route.metric,
    }
    if route.dst == "default":
        args["dst"] = "0.0.0.0/0" if route.family == 4 else "::/0"
    else:
        args["dst"] = route.dst
    if for_delete:
        # Match like `ip route del`: any scope, any protocol. pyroute2's
        # default scope (universe) never matches a device route (scope link),
        # so the delete fails with ESRCH.
        args["scope"] = 255
        args["proto"] = 0
    else:
        if route.dev is not None:
            matches = ipr.link_lookup(ifname=route.dev)
            if not matches:
                raise ApplyError(f"route {route}: no such device {route.dev}")
            args["oif"] = matches[0]
        if route.gateway is not None:
            args["gateway"] = route.gateway
    return args

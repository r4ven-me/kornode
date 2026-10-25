"""Local agent CLI (spec 06). Runtime changes go through owner-only RPC."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

from kornode.tunnels.argv import DialSpec, openconnect_argv
from kornode_agent.agent import Agent, _component_versions
from kornode_agent.config import load_config, save_config
from kornode_agent.control import ControlClient, ControlError, HubUnreachable
from kornode_agent.enroll import EnrollToken, TokenError, enroll, is_enrolled, parse_token
from kornode_agent.inspection import (
    Redactor,
    bundle_history,
    bundle_show,
    offline_status,
    write_archive,
)
from kornode_agent.local import LocalError, ProcessLock, Request, request
from kornode_agent.probes import link_exists
from kornode_agent.store import StoreError
from kornode_agent.tunnels import SubprocessRunner

DEFAULT_ROOT = "/var/lib/kornode-agent"
ENROLL_INTERFACE = "oc-enroll0"
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_CONFLICT, EXIT_HUB_UNREACHABLE = 0, 1, 2, 3, 4


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse normally echoes the offending value, which might be a token.
        raise LocalError("usage", "invalid command arguments; use --help", EXIT_USAGE)


def _positive(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 2**31 - 1:
        raise ValueError("version outside range")
    return number


HOST_NAME = re.compile(
    r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="kornode-agent")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--root", default=os.environ.get("KORNODE_AGENT_DIR", DEFAULT_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("enroll", help="one-time enrollment with a token from the hub")
    one.add_argument("token")
    one.add_argument("--force", action="store_true", help="enroll again over an existing identity")
    sub.add_parser("run", help="main process (used by the supervisor)")
    one = sub.add_parser(
        "set-hub-name", help="set the hub vhost name (SNI) in agent.yaml; agent must be stopped"
    )
    one.add_argument("server_name", help="e.g. interlink.<interlink domain>")
    sub.add_parser("version", help="versions of the agent and its components")
    sub.add_parser("status", help="live status, or offline local state")
    one = sub.add_parser("explain", help="explain a routing decision")
    one.add_argument("src", help="source IP or host")
    one.add_argument("dst", help="destination IP")
    one.add_argument("--proto", choices=("tcp", "udp", "icmp", "icmpv6"))
    one.add_argument("--port", type=int)
    sub.add_parser("doctor", help="read-only local network checks")
    one = sub.add_parser("diag", help="write a redacted diagnostic archive")
    one.add_argument("--out", type=Path)
    one = sub.add_parser("reconnect", help="restart a tunnel (default: all)")
    one.add_argument("tunnel", nargs="?")
    one.add_argument("--dry-run", action="store_true")
    one = sub.add_parser("bundle", help="inspect cached bundles or roll back")
    bundles = one.add_subparsers(dest="bundle_command", required=True)
    show = bundles.add_parser("show", help="verified bundle with secrets redacted")
    show.add_argument("version", nargs="?", type=_positive)
    bundles.add_parser("history", help="cached versions and results")
    rollback = bundles.add_parser("rollback", help="apply a cached confirmed version")
    rollback.add_argument("version", type=_positive)
    rollback.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in raw
    # Accept --json at every nesting level without subparser default collisions.
    raw = [arg for arg in raw if arg != "--json"]
    try:
        try:
            args = _parser().parse_args(raw)
        except SystemExit as exc:  # --help, not a usage error (handled by _Parser)
            return int(exc.code or 0)
        result, code = _command(Path(args.root), args)
        _print_result(result, json_output)
        return code
    except LocalError as exc:
        error = exc
    except (StoreError, OSError, ValueError):
        error = LocalError(
            "local_data", "cannot read local data or write output; check enrollment and permissions"
        )
    except Exception as exc:
        # Type only: messages may carry secrets (see the local server).
        print(f"kornode-agent: unexpected {type(exc).__name__}", file=sys.stderr)
        error = LocalError("internal_error", "command failed; inspect agent diagnostics")
    if json_output:
        print(json.dumps(error.as_dict()))
    else:
        print(f"{error.error}: {error}", file=sys.stderr)
    return error.exit_code


def _print_result(result: dict[str, object], json_output: bool) -> None:
    safe = Redactor().data(result)
    if json_output:
        print(json.dumps(safe, sort_keys=True))
    else:
        for key, value in safe.items():
            shown = json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value)
            print(f"{key}: {shown}")


def _command(root: Path, args: argparse.Namespace) -> tuple[dict[str, object], int]:
    if args.command == "version":
        return dict(_component_versions()), EXIT_OK
    if args.command == "enroll":
        return _enroll(root, args.token, force=args.force), EXIT_OK
    if args.command == "set-hub-name":
        return _set_hub_name(root, args.server_name), EXIT_OK
    if args.command == "run":
        code = _run(root)
        return {"stopped": True, "exit_code": code}, code
    if args.command == "bundle" and args.bundle_command != "rollback":
        result = (
            bundle_show(root, args.version)
            if args.bundle_command == "show"
            else bundle_history(root)
        )
        return result, EXIT_OK
    op = "rollback" if args.command == "bundle" else args.command
    fields = {
        key: getattr(args, key)
        for key in ("src", "dst", "proto", "port", "version", "tunnel", "dry_run")
        if hasattr(args, key) and getattr(args, key) is not None
    }
    try:
        req = Request.model_validate({"op": op, **fields})
    except ValueError:
        raise LocalError("usage", "invalid action arguments; use --help", EXIT_USAGE) from None
    if op == "diag" and args.out and (args.out.exists() or args.out.is_symlink()):
        raise LocalError("output_exists", "output already exists; choose a new --out path", 3)
    try:
        result = request(root, req)
    except LocalError as exc:
        if op != "status" or exc.error != "agent_unavailable":
            raise
        return offline_status(root), EXIT_OK
    if op == "diag":
        try:
            data = base64.b64decode(result["archive_b64"], validate=True)
        except (KeyError, ValueError, TypeError):
            raise LocalError("invalid_archive", "agent returned an invalid archive") from None
        if len(data) > 5 * 1024 * 1024:
            raise LocalError("invalid_archive", "archive exceeds 5 MiB")
        path = args.out or Path(f"kornode-agent-diag-{time.time_ns()}.tar.gz")
        write_archive(path, data)
        return {"path": str(path), "bytes": len(data)}, EXIT_OK
    code = EXIT_OK
    if op == "status" and result.get("hub_reachable") is False:
        code = EXIT_HUB_UNREACHABLE
    elif op == "doctor" and any(f.get("severity") == "error" for f in result["findings"]):
        code = EXIT_ERROR
    return result, code


def _run(root: Path) -> int:
    config = load_config(root)
    logging.basicConfig(
        level=config.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    async def runner() -> int:
        agent = Agent(root)
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, agent.stop.set)
        return await agent.run()

    return asyncio.run(runner())


def _set_hub_name(root: Path, server_name: str) -> dict[str, object]:
    """Point an enrolled agent at a renamed hub vhost (D-85): identity, key and pin stay."""
    name = server_name.strip().rstrip(".").lower()
    if not HOST_NAME.fullmatch(name):
        raise LocalError("invalid", "server name must be a DNS name", 2)
    with ProcessLock(root):
        config = load_config(root)
        previous = config.hub.server_name
        save_config(
            root,
            config.model_copy(update={"hub": config.hub.model_copy(update={"server_name": name})}),
        )
    return {"server_name": name, "previous": previous}


def _enroll(root: Path, text: str, *, force: bool) -> dict[str, object]:
    with ProcessLock(root):
        return _enroll_locked(root, text, force=force)


def _enroll_locked(root: Path, text: str, *, force: bool) -> dict[str, object]:
    if is_enrolled(root) and not force:
        raise LocalError("already_enrolled", "already enrolled; use --force to enroll again", 3)
    try:
        token = parse_token(text)
    except TokenError:
        raise LocalError("usage", "invalid enrollment token", EXIT_USAGE) from None
    try:
        with _enroll_session(root, token):
            asyncio.run(_exchange(root, token))
    except (HubUnreachable, OSError):
        raise LocalError(
            "hub_unreachable", "enrollment hub is unreachable", EXIT_HUB_UNREACHABLE
        ) from None
    except (ControlError, TokenError, StoreError, RuntimeError):
        raise LocalError(
            "enrollment_failed", "enrollment failed; check token validity and hub state"
        ) from None
    return {"enrolled": True, "node_id": load_config(root).node_id}


def _routed_through_enroll(host: str) -> bool:
    try:
        out = subprocess.run(
            ["ip", "-j", "route", "get", host], capture_output=True, text=True, timeout=5
        ).stdout
        return bool(json.loads(out)[0].get("dev") == ENROLL_INTERFACE)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError, KeyError):
        return False


ROUTE_WAIT_SECONDS = 10.0


def _wait_routed_through_enroll(host: str, *, timeout: float = ROUTE_WAIT_SECONDS) -> bool:
    """The interface exists as soon as openconnect backgrounds, but the
    vpnc-script installs the pushed routes a moment later. Wait for them, but
    never past the deadline: an unrouted hub address is refused, not sent."""
    deadline = time.monotonic() + timeout
    while not _routed_through_enroll(host):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)
    return True


async def _exchange(root: Path, token: EnrollToken) -> None:
    # The request is sent without server verification: it must stay inside the
    # pinned enroll session, never leak to the uplink.
    host = urlsplit(token.control_url).hostname or ""
    if not await asyncio.to_thread(_wait_routed_through_enroll, host):
        raise RuntimeError(f"{host} is not routed through {ENROLL_INTERFACE}; refusing to enroll")
    client = ControlClient.for_enroll(token.control_url)
    try:
        await enroll(root, token, client)
    finally:
        await client.aclose()


@contextlib.contextmanager
def _enroll_session(root: Path, token: EnrollToken):  # type: ignore[no-untyped-def]
    """The short-lived enroll openconnect session (pinned hub certificate).

    The distribution vpnc-script installs the routes the hub pushes to the
    `enroll` group; the hub's firewall confines the session to the control API.
    """
    run = root / "run"
    run.mkdir(parents=True, exist_ok=True, mode=0o700)
    pid_file = run / "oc-enroll.pid"
    spec = DialSpec(
        server=token.host,
        port=token.port,
        interface=ENROLL_INTERFACE,
        pid_file=pid_file,
        script=None,
        auth_type="password",
        username=token.user,
        password=token.secret,
        server_cert_pin=token.pin,
        camouflage_secret=token.camouflage,
        server_name=token.server_name,
    )
    config_path = None
    lines = []
    if token.camouflage:
        from kornode.tunnels.argv import config_lines
        from kornode_agent.store import atomic_write

        lines = config_lines(spec)
        config_path = run / "oc-enroll.conf"
        atomic_write(config_path, ("\n".join(lines) + "\n").encode(), 0o600)
    code = SubprocessRunner().run(
        openconnect_argv(spec, config_path=config_path),
        input_text=f"{token.secret}\n",
        timeout=60,
        log=root / "logs" / "openconnect-enroll.log",
    )
    if code != 0:
        raise OSError(f"could not open the enroll session (openconnect exited {code})")
    deadline = time.monotonic() + 10
    while not link_exists(ENROLL_INTERFACE):
        if time.monotonic() > deadline:
            raise OSError("the enroll tunnel interface did not appear")
        time.sleep(0.2)
    try:
        yield
    finally:
        with contextlib.suppress(OSError, ValueError):
            os.kill(int(pid_file.read_text().strip()), signal.SIGTERM)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""`kornode-agent` (spec 06 "CLI"). P3-06 ships enroll, run, version; the rest is P3-07."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from kornode.tunnels.argv import DialSpec, openconnect_argv
from kornode_agent.agent import Agent, _component_versions
from kornode_agent.config import load_config
from kornode_agent.control import ControlClient, ControlError, HubUnreachable
from kornode_agent.enroll import EnrollToken, TokenError, enroll, is_enrolled, parse_token
from kornode_agent.probes import link_exists
from kornode_agent.store import StoreError
from kornode_agent.tunnels import SubprocessRunner

DEFAULT_ROOT = "/var/lib/kornode-agent"
ENROLL_INTERFACE = "oc-enroll0"
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_HUB_UNREACHABLE = 0, 1, 2, 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kornode-agent")
    parser.add_argument("--root", default=os.environ.get("KORNODE_AGENT_DIR", DEFAULT_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("enroll", help="one-time enrollment with a token from the hub")
    one.add_argument("token")
    one.add_argument("--force", action="store_true", help="enroll again over an existing identity")
    sub.add_parser("run", help="main process (used by the supervisor)")
    sub.add_parser("version", help="versions of the agent and its components")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root)
    if args.command == "version":
        for name, value in _component_versions().items():
            print(f"{name}: {value}")
        return EXIT_OK
    if args.command == "enroll":
        return _enroll(root, args.token, force=args.force)
    return _run(root)


def _run(root: Path) -> int:
    try:
        config = load_config(root)
    except StoreError as exc:
        print(f"not enrolled: {exc}", file=sys.stderr)
        return EXIT_ERROR
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


def _enroll(root: Path, text: str, *, force: bool) -> int:
    if is_enrolled(root) and not force:
        print("already enrolled; use --force to enroll again", file=sys.stderr)
        return EXIT_ERROR
    try:
        token = parse_token(text)
    except TokenError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    try:
        with _enroll_session(root, token):
            asyncio.run(_exchange(root, token))
    except (HubUnreachable, OSError) as exc:
        print(f"hub unreachable: {exc}", file=sys.stderr)
        return EXIT_HUB_UNREACHABLE
    except (ControlError, TokenError, StoreError, RuntimeError) as exc:
        print(f"enrollment failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"enrolled as node {load_config(root).node_id}")
    return EXIT_OK


def _routed_through_enroll(host: str) -> bool:
    try:
        out = subprocess.run(
            ["ip", "-j", "route", "get", host], capture_output=True, text=True, timeout=5
        ).stdout
        return bool(json.loads(out)[0].get("dev") == ENROLL_INTERFACE)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError, KeyError):
        return False


async def _exchange(root: Path, token: EnrollToken) -> None:
    # The request is sent without server verification: it must stay inside the
    # pinned enroll session, never leak to the uplink.
    host = urlsplit(token.control_url).hostname or ""
    if not _routed_through_enroll(host):
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

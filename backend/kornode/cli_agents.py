"""Thin Typer adapters for the hub management services."""

from __future__ import annotations

import json as jsonlib
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from click import edit

from kornode.config.models import AppConfig
from kornode.services.agent_models import AgentCreate, AgentPatch, ManagementError, PrefixInput
from kornode.services.agents import AgentService, parse
from kornode.services.control_management import ControlManagement
from kornode.services.interlink_dns import DnsRecordInput, InterlinkDnsService

Json = Annotated[bool, typer.Option("--json", help="Machine-readable output")]


def emit(value: dict[str, Any], json_output: bool) -> None:
    if json_output:
        typer.echo(jsonlib.dumps(value))
        return
    rows = next((v for v in value.values() if isinstance(v, list)), None)
    if rows and all(isinstance(row, dict) for row in rows):
        keys = list(rows[0])
        texts = [[jsonlib.dumps(row.get(k), ensure_ascii=True)[:70] for k in keys] for row in rows]
        widths = [max(len(k), *(len(row[i]) for row in texts)) for i, k in enumerate(keys)]
        typer.echo("  ".join(k.ljust(widths[i]) for i, k in enumerate(keys)))
        for row in texts:
            typer.echo("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)))
    else:
        typer.echo(jsonlib.dumps(value, indent=2))


def invoke(
    function: Callable[..., dict[str, Any]], json_output: bool, *args: Any, **kwargs: Any
) -> None:
    try:
        emit(function(*args, **kwargs), json_output)
    except ManagementError as exc:
        value = exc.body()
        typer.echo(jsonlib.dumps(value), err=not json_output)
        raise typer.Exit(3 if exc.status in (404, 409) else 2 if exc.status == 422 else 1) from None
    except Exception:
        typer.echo(
            jsonlib.dumps(
                {
                    "error": "local_error",
                    "message": "management action failed; check local services and permissions",
                }
            ),
            err=not json_output,
        )
        raise typer.Exit(1) from None


def read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise ValueError()
        data = jsonlib.loads(path.read_text())
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (OSError, ValueError):
        raise ManagementError(
            422, "invalid", "expected a JSON object file no larger than 1 MiB"
        ) from None


def confirmed(yes: bool, dry_run: bool, json_output: bool, label: str) -> None:
    if dry_run or yes:
        return
    if json_output:
        raise ManagementError(
            422, "confirmation_required", "use --yes for non-interactive destructive actions"
        )
    if not typer.confirm(label):
        raise ManagementError(409, "cancelled", "action cancelled")


def publish(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(prefix=".diag-", dir=path.parent, delete=False) as handle:
        tmp = Path(handle.name)
        try:
            os.chmod(tmp, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.link(tmp, path)  # atomic no-clobber, including dangling symlinks
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            tmp.unlink(missing_ok=True)


def register(app: typer.Typer, config: Callable[[], AppConfig]) -> None:
    agent = typer.Typer(help="Manage hub agents")
    control = typer.Typer(help="Control-plane status and signing keys")
    prefix = typer.Typer(help="Agent exported networks")
    policy = typer.Typer(help="Agent egress policy")
    source = typer.Typer(help="Agent attached sources")
    upstream = typer.Typer(help="Agent external upstreams")
    user = typer.Typer(help="Access users of an agent with role access (delivered as hashes)")
    access = typer.Typer(help="Access listener (ocserv) of an agent with role access")
    bundle = typer.Typer(help="Agent bundle history and redacted views")

    def service() -> AgentService:
        return AgentService(config())

    @agent.command("list")
    def list_agents(json: Json = False) -> None:
        invoke(lambda: service().list(), json)

    @agent.command("show")
    def show(name: str, json: Json = False) -> None:
        invoke(lambda: service().show(name), json)

    @agent.command("create")
    def create(
        name: str,
        id: int | None = None,
        role: list[str] = typer.Option([], "--role", help="access and/or gateway"),
        description: str = "",
        force_reuse: bool = False,
        dry_run: bool = False,
        json: Json = False,
    ) -> None:
        invoke(
            lambda: service().create(
                parse(
                    AgentCreate,
                    {
                        "name": name,
                        "id": id,
                        "roles": role,
                        "description": description,
                        "force_reuse": force_reuse,
                        "dry_run": dry_run,
                    },
                )
            ),
            json,
        )

    @agent.command("set")
    def update(
        name: str,
        description: str | None = None,
        role: list[str] | None = typer.Option(None, "--role", help="access and/or gateway"),
        transport: str | None = None,
        dpd: int | None = None,
        keepalive: int | None = None,
        file: Path | None = None,
        json: Json = False,
    ) -> None:
        def action() -> dict[str, Any]:
            data = read_json(file) if file else {}
            if description is not None:
                data["description"] = description
            if role is not None:
                data["roles"] = role
            tuning = {
                k: v
                for k, v in (("transport", transport), ("dpd", dpd), ("keepalive", keepalive))
                if v is not None
            }
            if tuning:
                data["transport"] = {**data.get("transport", {}), **tuning}
            return service().update(name, parse(AgentPatch, data))

        invoke(action, json)

    @agent.command("token")
    def token(name: str, revoke: bool = False, json: Json = False) -> None:
        invoke(lambda: service().token(name, revoke=revoke), json)

    @agent.command("push")
    def push(name: str, dry_run: bool = False, json: Json = False) -> None:
        """Compile and serve a new bundle version even if its content is unchanged."""
        invoke(lambda: service().push(name, dry_run=dry_run), json)

    @agent.command("revoke")
    def revoke(name: str, yes: bool = False, dry_run: bool = False, json: Json = False) -> None:
        def action() -> dict[str, Any]:
            confirmed(yes, dry_run, json, f"Revoke and disconnect agent {name}?")
            return service().revoke(name, dry_run=dry_run)

        invoke(action, json)

    @agent.command("delete")
    def delete(name: str, yes: bool = False, dry_run: bool = False, json: Json = False) -> None:
        def action() -> dict[str, Any]:
            confirmed(
                yes, dry_run, json, f"Revoke and delete agent {name} (id quarantine 30 days)?"
            )
            return service().delete(name, dry_run=dry_run)

        invoke(action, json)

    @prefix.command("list")
    def prefix_list(name: str, json: Json = False) -> None:
        invoke(lambda: service().prefixes(name), json)

    @prefix.command("add")
    def prefix_add(
        name: str,
        cidr: str,
        kind: str = "lan",
        export: bool = typer.Option(True, "--export/--no-export"),
        json: Json = False,
    ) -> None:
        invoke(
            lambda: service().add_prefix(
                name, parse(PrefixInput, {"prefix": cidr, "kind": kind, "export": export})
            ),
            json,
        )

    @prefix.command("del")
    def prefix_del(name: str, cidr: str, json: Json = False) -> None:
        invoke(lambda: service().delete_prefix(name, cidr), json)

    @policy.command("show")
    def policy_show(name: str, json: Json = False) -> None:
        invoke(lambda: service().policy(name), json)

    @policy.command("set")
    def policy_set(name: str, file: Path = typer.Option(..., "--file"), json: Json = False) -> None:
        invoke(lambda: service().set_policy(name, read_json(file)), json)

    @policy.command("edit")
    def policy_edit(name: str, json: Json = False) -> None:
        def action() -> dict[str, Any]:
            if json:
                raise ManagementError(
                    422, "usage", "use egress set --file for non-interactive editing"
                )
            text = edit(
                jsonlib.dumps(service().policy(name)["policy"], indent=2), extension=".json"
            )
            if text is None:
                raise ManagementError(409, "cancelled", "edit cancelled")
            try:
                data = jsonlib.loads(text)
            except ValueError:
                raise ManagementError(422, "invalid", "editor returned invalid JSON") from None
            return service().set_policy(name, data)

        invoke(action, json)

    @source.command("list")
    def source_list(name: str, json: Json = False) -> None:
        invoke(lambda: service().sources(name), json)

    @source.command("add")
    @source.command("set")
    def source_set(
        name: str, source: str, file: Path = typer.Option(..., "--file"), json: Json = False
    ) -> None:
        invoke(lambda: service().set_source(name, source, read_json(file)), json)

    @source.command("del")
    def source_del(name: str, source: str, json: Json = False) -> None:
        invoke(lambda: service().set_source(name, source, None), json)

    @upstream.command("list")
    def upstream_list(name: str, json: Json = False) -> None:
        invoke(lambda: service().upstreams(name), json)

    @upstream.command("add")
    @upstream.command("set")
    def upstream_set(
        name: str, upstream: str, file: Path = typer.Option(..., "--file"), json: Json = False
    ) -> None:
        invoke(lambda: service().set_upstream(name, upstream, read_json(file)), json)

    @upstream.command("del")
    def upstream_del(name: str, upstream: str, json: Json = False) -> None:
        invoke(lambda: service().set_upstream(name, upstream, None), json)

    @access.command("show")
    def access_show(name: str, json: Json = False) -> None:
        invoke(lambda: service().access(name), json)

    @access.command("set")
    def access_set(
        name: str,
        hostname: Annotated[str, typer.Option(help="Public DNS name or IP of the listener")],
        port: int = 443,
        udp: bool = False,
        reissue: bool = typer.Option(False, help="Issue a new server certificate"),
        json: Json = False,
    ) -> None:
        payload = {"hostname": hostname, "port": port, "udp": udp, "reissue": reissue}
        invoke(lambda: service().set_access(name, payload), json)

    @access.command("del")
    def access_del(name: str, json: Json = False) -> None:
        invoke(lambda: service().set_access(name, None), json)

    @user.command("list")
    def user_list(name: str, json: Json = False) -> None:
        invoke(lambda: service().users(name), json)

    def password(stdin: bool) -> str:
        if stdin:
            import sys

            return sys.stdin.readline(1026).rstrip("\n")
        return str(typer.prompt("Password", hide_input=True, confirmation_prompt=True))

    @user.command("add")
    def user_add(
        name: str,
        username: str,
        group: list[str] = typer.Option([], "--group"),
        password_stdin: bool = False,
        json: Json = False,
    ) -> None:
        invoke(
            lambda: service().set_user(
                name, username, {"password": password(password_stdin), "groups": group}
            ),
            json,
        )

    @user.command("passwd")
    def user_passwd(
        name: str, username: str, password_stdin: bool = False, json: Json = False
    ) -> None:
        invoke(
            lambda: service().set_user(name, username, {"password": password(password_stdin)}), json
        )

    @user.command("set")
    def user_set(
        name: str, username: str, file: Path = typer.Option(..., "--file"), json: Json = False
    ) -> None:
        invoke(lambda: service().set_user(name, username, read_json(file)), json)

    @user.command("enable")
    def user_enable(name: str, username: str, json: Json = False) -> None:
        invoke(lambda: service().set_user(name, username, {"enabled": True}), json)

    @user.command("disable")
    def user_disable(name: str, username: str, json: Json = False) -> None:
        invoke(lambda: service().set_user(name, username, {"enabled": False}), json)

    @user.command("del")
    def user_del(name: str, username: str, json: Json = False) -> None:
        invoke(lambda: service().set_user(name, username, None), json)

    @bundle.command("list")
    def bundle_list(name: str, json: Json = False) -> None:
        invoke(lambda: service().bundles_list(name), json)

    @bundle.command("show")
    def bundle_show(name: str, version: int, json: Json = False) -> None:
        invoke(lambda: service().bundle(name, version), json)

    @bundle.command("diff")
    def bundle_diff(name: str, a: int, b: int, json: Json = False) -> None:
        invoke(lambda: service().bundle_diff(name, a, b), json)

    @agent.command("status")
    def status(name: str, limit: int = 50, watch: bool = False, json: Json = False) -> None:
        try:
            while True:
                invoke(lambda: service().reports(name, limit), json)
                if not watch:
                    return
                time.sleep(5)
        except KeyboardInterrupt:
            return

    @agent.command("exec")
    def execute(
        name: str,
        command: str,
        tunnel: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        proto: str | None = None,
        port: int | None = None,
        to_version: int | None = None,
        yes: bool = False,
        dry_run: bool = False,
        json: Json = False,
    ) -> None:
        args = {
            k: v
            for k, v in (
                ("tunnel", tunnel),
                ("src", src),
                ("dst", dst),
                ("proto", proto),
                ("port", port),
                ("to_version", to_version),
            )
            if v is not None
        }

        def action() -> dict[str, Any]:
            kind = command.replace("-", "_")
            if kind in ("reconnect", "restart", "rollback"):
                confirmed(yes, dry_run, json, f"Queue {kind} for agent {name}?")
            return service().enqueue(name, {"type": kind, "args": args, "dry_run": dry_run})

        invoke(action, json)

    @agent.command("commands")
    def commands(name: str, json: Json = False) -> None:
        invoke(lambda: service().commands(name), json)

    @agent.command("command")
    def command_result(
        name: str, command_id: str, out: Path | None = None, json: Json = False
    ) -> None:
        def action() -> dict[str, Any]:
            if out is not None:
                publish(out, service().artifact(name, command_id))
                return {"path": str(out)}
            return service().command(name, command_id)

        invoke(action, json)

    @control.command("status")
    def control_status(json: Json = False) -> None:
        invoke(lambda: ControlManagement(config()).status(), json)

    @control.command("rotate-signing-key")
    def rotate(yes: bool = False, dry_run: bool = False, json: Json = False) -> None:
        def action() -> dict[str, Any]:
            confirmed(
                yes, dry_run, json, "Announce a new signing key and promote it in seven days?"
            )
            return ControlManagement(config()).rotate(dry_run=dry_run)

        invoke(action, json)

    for name, group in (
        ("prefix", prefix),
        ("egress", policy),
        ("source", source),
        ("upstream", upstream),
        ("user", user),
        ("access", access),
        ("bundle", bundle),
    ):
        agent.add_typer(group, name=name)
    app.add_typer(agent, name="agent")
    app.add_typer(control, name="control")
    register_dns(app, config)


def register_dns(app: typer.Typer, config: Callable[[], AppConfig]) -> None:
    dns = typer.Typer(help="Interlink DNS zone (interlink.domain)")
    record = typer.Typer(help="Zone records; --node scopes a name to node<id>.<domain>")

    def service() -> InterlinkDnsService:
        return InterlinkDnsService(config())

    def entry(name: str, type_: str, value: str, node: str | None) -> DnsRecordInput:
        return parse(
            DnsRecordInput, {"name": name, "type": type_.upper(), "value": value, "node": node}
        )

    @record.command("list")
    def record_list(json: Json = False) -> None:
        invoke(lambda: service().list(), json)

    @record.command("add")
    def record_add(
        name: str,
        type_: Annotated[str, typer.Argument(metavar="TYPE", help="A, AAAA or CNAME")],
        value: str,
        node: Annotated[str | None, typer.Option(help="Agent name; default hub-wide")] = None,
        json: Json = False,
    ) -> None:
        invoke(lambda: service().add(entry(name, type_, value, node)), json)

    @record.command("del")
    def record_del(
        name: str,
        type_: Annotated[str, typer.Argument(metavar="TYPE", help="A, AAAA or CNAME")],
        value: str,
        node: Annotated[str | None, typer.Option(help="Agent name; default hub-wide")] = None,
        json: Json = False,
    ) -> None:
        invoke(lambda: service().delete(entry(name, type_, value, node)), json)

    dns.add_typer(record, name="record")
    app.add_typer(dns, name="dns")

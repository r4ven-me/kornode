from __future__ import annotations

import datetime
import socket
from collections.abc import Sequence
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.sessions import SessionRecord, SessionService


class FailingRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        return CommandResult(tuple(argv), 1, "", "occtl unavailable")


class SessionDetailRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(
                tuple(argv),
                0,
                "Username  IP           Connected\nlans      77.83.3.157  vpns0\n",
                "",
            )
        if tuple(argv[-3:]) == ("show", "user", "lans"):
            return CommandResult(
                tuple(argv),
                0,
                """
username: lans
IP: 10.10.10.2
Remote IP: 77.83.3.157
Connected since: 2026-06-29 14:00
RX: 10 MiB
TX: 2 MiB
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


class RealOcctlDetailRunner(CommandRunner):
    """Mirrors real-world occtl output, which uses "Device"/"Last connected
    at"/"Session started at" rather than the older "Connected since" field."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(
                tuple(argv),
                0,
                "Username  IP           Connected\nlans      77.83.3.157  oc-client0\n",
                "",
            )
        if tuple(argv[-3:]) == ("show", "user", "lans"):
            return CommandResult(
                tuple(argv),
                0,
                """
ID: 112
Username: lans
Groupname: (none)
State: connected
vhost: default
Device: oc-client0
MTU: 1434
Remote IP: 77.83.3.157
Location: unknown
Local Device IP: 161.104.32.226
IPv4: 10.207.207.28
P-t-P IPv4: 10.207.207.1
User-Agent: AnyConnect Android 5.1.15.344
RX: 214690 (214.7 kB)
TX: 102802 (102.8 kB)
Average bandwidth RX: 1.4 kB/s TX: 658 bytes/s
DPD: 90
KeepAlive: 32400
Hostname: wtf
Last connected at: 2026-07-04 19:00 ( 2m:36s)
Session started at: 2026-07-04 19:00 ( 2m:36s)
Session: xHZYg0
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


class SessionIdRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(tuple(argv), 0, "", "")
        if tuple(argv[-3:]) == ("show", "sessions", "all"):
            return CommandResult(tuple(argv), 0, "SID\nabc123\n", "")
        if tuple(argv[-3:]) == ("show", "session", "abc123"):
            return CommandResult(
                tuple(argv),
                0,
                """
User: lans
IP: 10.10.10.28
Remote IP: 77.83.3.157
Connected since: 2026-06-30 10:00 (32s)
RX: 1000 TX: 2000
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


class SessionSummaryWithoutConnectedRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users") and "--json" in argv:
            return CommandResult(tuple(argv), 1, "", "json unavailable")
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(
                tuple(argv),
                0,
                "Username  IP           Connected\nlans      77.83.3.157  vpns0\n",
                "",
            )
        if tuple(argv[-3:]) == ("show", "user", "lans"):
            return CommandResult(tuple(argv), 1, "", "not available")
        if tuple(argv[-3:]) == ("show", "sessions", "all") and "--json" in argv:
            return CommandResult(tuple(argv), 1, "", "json unavailable")
        if tuple(argv[-3:]) == ("show", "sessions", "all"):
            return CommandResult(tuple(argv), 0, "SID\nabc123\n", "")
        if tuple(argv[-3:]) == ("show", "session", "abc123"):
            return CommandResult(
                tuple(argv),
                0,
                """
User: lans
IP: 10.10.10.10
Remote IP: 77.83.3.157
Connected since: 2026-07-01 12:30 (44s)
RX: 25.4 KB
TX: 18.8 KB
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


class SessionSummaryOnlyRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users") and "--json" in argv:
            return CommandResult(tuple(argv), 1, "", "json unavailable")
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(
                tuple(argv),
                0,
                "Username  IP           Connected     RX       TX\n"
                "lans      77.83.3.157  vpns0         24.6 KB  21.3 KB\n",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not available")


class JsonSessionRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users") and "--json" in argv:
            return CommandResult(
                tuple(argv),
                0,
                """
[
  {
    "Username": "lans",
    "IP": "10.10.10.28",
    "Remote IP": "77.83.3.157",
    "Connected since": "2026-06-30 10:00",
    "RX": "40.9 KB",
    "TX": "74.3 KB"
  }
]
""",
                "",
            )
        if tuple(argv[-3:]) == ("show", "user", "lans") and "--json" in argv:
            return CommandResult(
                tuple(argv),
                0,
                """
{
  "User": "lans",
  "IP": "10.10.10.28",
  "Remote IP": "77.83.3.157",
  "Connected since": "2026-06-30 10:00 (32s)",
  "raw_rx": 40856,
  "raw_tx": 74339,
  "Average RX": "12 bytes/sec",
  "Average TX": "34 bytes/sec"
}
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


class LooseSessionRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        if tuple(argv[-2:]) == ("show", "users"):
            return CommandResult(tuple(argv), 0, "lans 77.83.3.157 vpns0\n", "")
        if tuple(argv[-3:]) == ("show", "user", "lans"):
            return CommandResult(
                tuple(argv),
                0,
                """
User: lans
IP: 10.10.10.28
Remote IP: 77.83.3.157
Connected since: 2026-06-30 10:00 (32s)
RX: 40856
TX: 74339
""",
                "",
            )
        return CommandResult(tuple(argv), 1, "", "not found")


def test_list_sessions_returns_empty_when_occtl_fails() -> None:
    service = SessionService(AppConfig(), runner=FailingRunner())

    assert service.list_sessions() == []


def test_parse_sessions_keeps_internal_and_external_ips_separate() -> None:
    output = """
username: alice
IP: 10.10.10.14
Remote IP: 203.0.113.9
Connected since: 2026-06-29 12:00
RX: 1.5 MiB
TX: 620 KiB
"""
    sessions = SessionService(AppConfig()).parse_sessions(output)

    assert len(sessions) == 1
    duration = sessions[0].duration_seconds
    assert duration is not None and duration > 0
    assert sessions[0] == SessionRecord(
        username="alice",
        vpn_ip="10.10.10.14",
        real_ip="203.0.113.9",
        rx="1.5 MiB",
        tx="620 KiB",
        duration_seconds=duration,
    )


def test_parse_table_sessions() -> None:
    output = """
Username  VPN IP       Real IP       Connected          Download  Upload
alice     10.10.10.14  203.0.113.9   00:03:21           1 MiB     2 MiB
"""
    sessions = SessionService(AppConfig()).parse_sessions(output)

    assert sessions[0].username == "alice"
    assert sessions[0].vpn_ip == "10.10.10.14"
    assert sessions[0].real_ip == "203.0.113.9"
    assert sessions[0].rx == "1 MiB"
    assert sessions[0].tx == "2 MiB"
    # "00:03:21" is an elapsed-time string, not a device name.
    assert sessions[0].device is None
    assert sessions[0].duration_seconds == 201


def test_summary_ip_is_external_and_device_is_interface() -> None:
    output = """
Username  IP           Connected
lans      77.83.3.157  vpns0
"""
    sessions = SessionService(AppConfig()).parse_sessions(output)

    assert sessions[0].username == "lans"
    assert sessions[0].vpn_ip is None
    assert sessions[0].real_ip == "77.83.3.157"
    assert sessions[0].device == "vpns0"
    assert sessions[0].duration_seconds is None


def test_parse_loose_show_users_row_without_header() -> None:
    sessions = SessionService(AppConfig()).parse_sessions("lans 77.83.3.157 vpns0\n")

    assert sessions == [
        SessionRecord(username="lans", vpn_ip=None, real_ip="77.83.3.157")
    ]


def test_parse_loose_row_splits_vpn_and_real_ips() -> None:
    sessions = SessionService(AppConfig()).parse_sessions(
        "lans 10.10.10.28 77.83.3.157 vpns0\n"
    )

    assert sessions == [
        SessionRecord(username="lans", vpn_ip="10.10.10.28", real_ip="77.83.3.157")
    ]


def test_list_sessions_enriches_summary_with_user_details() -> None:
    sessions = SessionService(AppConfig(), runner=SessionDetailRunner()).list_sessions()

    # duration_seconds is derived from the detail lookup's "Connected since"
    # timestamp relative to now, so it can't be asserted as an exact constant.
    assert len(sessions) == 1
    duration = sessions[0].duration_seconds
    assert duration is not None and duration > 0
    assert sessions[0] == SessionRecord(
        username="lans",
        vpn_ip="10.10.10.2",
        real_ip="77.83.3.157",
        device="vpns0",
        rx="10 MiB",
        tx="2 MiB",
        duration_seconds=duration,
    )


def test_list_sessions_computes_duration_from_real_occtl_detail_fields() -> None:
    sessions = SessionService(AppConfig(), runner=RealOcctlDetailRunner()).list_sessions()

    assert len(sessions) == 1
    assert sessions[0].username == "lans"
    assert sessions[0].vpn_ip == "10.207.207.28"
    assert sessions[0].real_ip == "77.83.3.157"
    # Device should show the client's interface, not the timestamp.
    assert sessions[0].device == "oc-client0"
    assert sessions[0].duration_seconds == 156


def test_list_sessions_enriches_loose_summary_with_user_details() -> None:
    sessions = SessionService(AppConfig(), runner=LooseSessionRunner()).list_sessions()

    # No "Device:" field is present anywhere in this occtl output, so device
    # stays unset rather than falling back to showing the timestamp.
    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip="10.10.10.28",
            real_ip="77.83.3.157",
            rx="40856",
            tx="74339",
            duration_seconds=32,
        )
    ]


def test_parse_combined_rx_tx_line_splits_traffic() -> None:
    sessions = SessionService(AppConfig()).parse_sessions(
        """
username: lans
IP: 10.10.10.28
Remote IP: 77.83.3.157
RX: 40856 (40.9 KB) TX: 74339 (74.3 KB)
"""
    )

    assert sessions[0].rx == "40856 (40.9 KB)"
    assert sessions[0].tx == "74339 (74.3 KB)"


def test_list_sessions_prefers_occtl_json_output() -> None:
    sessions = SessionService(AppConfig(), runner=JsonSessionRunner()).list_sessions()

    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip="10.10.10.28",
            real_ip="77.83.3.157",
            rx="40856 bytes",
            tx="74339 bytes",
            rx_rate="12 bytes/sec",
            tx_rate="34 bytes/sec",
            duration_seconds=32,
        )
    ]


def test_json_session_accepts_connection_time_alias() -> None:
    sessions = SessionService(AppConfig()).parse_json_sessions(
        """
{
  "Username": "lans",
  "IP": "10.10.10.28",
  "Remote IP": "77.83.3.157",
  "Connection time": "2026-06-30 10:00 (32s)",
  "raw_rx": 40856,
  "raw_tx": 74339
}
"""
    )

    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip="10.10.10.28",
            real_ip="77.83.3.157",
            rx="40856 bytes",
            tx="74339 bytes",
            duration_seconds=32,
        )
    ]


def test_json_session_duration_survives_two_day_old_sessions() -> None:
    """occtl JSON prints "Session started at" (absolute date) followed by
    "_Session started at" (elapsed); normalization collapses both into one
    key with the elapsed string winning, and after 48h that string becomes
    " 3days". The raw_* epoch fields must take priority so the duration does
    not vanish for long-lived sessions."""
    started = int(datetime.datetime.now().timestamp()) - 3 * 86400

    sessions = SessionService(AppConfig()).parse_json_sessions(
        f"""
{{
  "Username": "wh1te",
  "IPv4": "10.207.207.101",
  "Remote IP": "77.83.3.157",
  "Device": "kor-client3",
  "Last connected at": "2026-07-15 08:00",
  "_Last connected at": " 3days",
  "Session started at": "2026-07-15 08:00",
  "_Session started at": " 3days",
  "raw_connected_at": {started},
  "raw_session_started_at": {started}
}}
"""
    )

    assert len(sessions) == 1
    duration = sessions[0].duration_seconds
    assert duration is not None
    assert 3 * 86400 <= duration <= 3 * 86400 + 60


def test_json_session_ignores_zero_epoch_placeholder() -> None:
    """ocserv reports raw times of 0 when unknown; duration must then come
    from the elapsed string instead of a bogus 1970-based epoch."""
    sessions = SessionService(AppConfig()).parse_json_sessions(
        """
{
  "Username": "wh1te",
  "_Session started at": " 3days",
  "raw_connected_at": 0,
  "raw_session_started_at": 0
}
"""
    )

    assert len(sessions) == 1
    assert sessions[0].duration_seconds == 3 * 86400


def test_list_sessions_falls_back_to_session_ids() -> None:
    sessions = SessionService(AppConfig(), runner=SessionIdRunner()).list_sessions()

    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip="10.10.10.28",
            real_ip="77.83.3.157",
            rx="1000",
            tx="2000",
            duration_seconds=32,
        )
    ]


def test_list_sessions_fills_missing_device_from_session_detail() -> None:
    sessions = SessionService(
        AppConfig(),
        runner=SessionSummaryWithoutConnectedRunner(),
    ).list_sessions()

    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip="10.10.10.10",
            real_ip="77.83.3.157",
            device="vpns0",
            rx="25.4 KB",
            tx="18.8 KB",
            duration_seconds=44,
        )
    ]


def test_list_sessions_keeps_active_summary_interface_without_since() -> None:
    sessions = SessionService(AppConfig(), runner=SessionSummaryOnlyRunner()).list_sessions()

    assert sessions == [
        SessionRecord(
            username="lans",
            vpn_ip=None,
            real_ip="77.83.3.157",
            device="vpns0",
            rx="24.6 KB",
            tx="21.3 KB",
        )
    ]


def test_control_socket_prefers_occtl_socket(tmp_path: Path) -> None:
    control_socket = socket.socket(socket.AF_UNIX)
    worker_socket = socket.socket(socket.AF_UNIX)
    try:
        control_socket.bind(str(tmp_path / "occtl.sock"))
        worker_socket.bind(str(tmp_path / "ocserv.sock.worker"))
        config = AppConfig.model_validate({"system": {"generated_dir": tmp_path}})

        service = SessionService(config)

        assert service.control_socket() == str(tmp_path / "occtl.sock")
    finally:
        control_socket.close()
        worker_socket.close()


def test_parse_duration_seconds_prefers_parenthetical_suffix() -> None:
    assert SessionService._parse_duration_seconds("2026-06-30 10:00 (32s)") == 32
    assert SessionService._parse_duration_seconds("2026-06-30 10:00 (1h2m3s)") == 3723


def test_parse_duration_seconds_from_bare_compact_duration() -> None:
    assert SessionService._parse_duration_seconds("32s") == 32
    assert SessionService._parse_duration_seconds("5m") == 300
    assert SessionService._parse_duration_seconds("2d3h") == 2 * 86400 + 3 * 3600


def test_parse_duration_seconds_from_occtl_ival7_formats() -> None:
    """occtl's print_time_ival7 output: "  32s", " 2m:36s", "36h:00m" and,
    once a session is 2+ days old, " 3days"."""
    assert SessionService._parse_duration_seconds("  32s") == 32
    assert SessionService._parse_duration_seconds(" 2m:36s") == 156
    assert SessionService._parse_duration_seconds("36h:00m") == 36 * 3600
    assert SessionService._parse_duration_seconds(" 3days") == 3 * 86400
    assert SessionService._parse_duration_seconds("2026-07-15 08:00 ( 3days)") == 3 * 86400


def test_parse_duration_seconds_from_table_hhmmss() -> None:
    assert SessionService._parse_duration_seconds("00:03:21") == 201
    assert SessionService._parse_duration_seconds("1:02:03") == 3723


def test_parse_duration_seconds_from_absolute_timestamp() -> None:
    connected_at = datetime.datetime.now() - datetime.timedelta(seconds=300)
    text = connected_at.strftime("%Y-%m-%d %H:%M:%S")

    duration = SessionService._parse_duration_seconds(text)

    assert duration is not None
    assert 295 <= duration <= 320


def test_parse_duration_seconds_returns_none_for_interface_name() -> None:
    assert SessionService._parse_duration_seconds("vpns0") is None
    assert SessionService._parse_duration_seconds("Connected") is None
    assert SessionService._parse_duration_seconds(None) is None


class KickFallbackRunner(CommandRunner):
    """occtl that cannot disconnect by name but knows workers by ID."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, dry_run, extra_secrets
        self.calls.append(tuple(argv))
        joined = " ".join(argv)
        if "disconnect user" in joined:
            return CommandResult(tuple(argv), 1, "", "user 'alice' not found")
        if "-j show users" in joined or ("show users" in joined and "-j" in joined):
            return CommandResult(
                tuple(argv),
                0,
                '[{"ID": 41, "Username": "alice"}, {"ID": 42, "Username": "alice"},'
                ' {"ID": 50, "Username": "bob"}]',
                "",
            )
        if "disconnect id" in joined:
            return CommandResult(tuple(argv), 0, "connection disconnected", "")
        return CommandResult(tuple(argv), 1, "", "not found")


def test_kick_falls_back_to_worker_ids() -> None:
    runner = KickFallbackRunner()
    result = SessionService(AppConfig(), runner=runner).kick("alice")

    assert result.returncode == 0
    disconnect_ids = [call for call in runner.calls if "id" in call and "disconnect" in call]
    assert len(disconnect_ids) == 2
    assert not any("50" in call for call in disconnect_ids)


def test_kick_reports_half_open_sessions_without_500() -> None:
    result = SessionService(AppConfig(), runner=FailingRunner()).kick("alice")

    assert result.returncode == 1
    assert "expire on their own" in result.stderr

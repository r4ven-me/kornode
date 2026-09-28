from __future__ import annotations

import datetime
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner

# occtl's print_time_ival7 switches format with age: "  32s", " 2m:36s",
# "36h:00m", then " 3days" once the session is 2+ days old — the unit may be
# a bare letter or a full word.
_DURATION_TOKEN_RE = re.compile(
    r"(\d+)\s*(days?|hours?|hrs?|minutes?|mins?|seconds?|secs?|d|h|m|s)(?![a-z])",
    re.IGNORECASE,
)
_PAREN_RE = re.compile(r"\(([^)]*)\)")
_HHMMSS_RE = re.compile(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$")
_ABS_DATETIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{1,2}:\d{2}(?::\d{2})?)")
_DURATION_UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


@dataclass(frozen=True)
class SessionRecord:
    username: str
    vpn_ip: str | None = None
    real_ip: str | None = None
    device: str | None = None
    rx: str | None = None
    tx: str | None = None
    rx_rate: str | None = None
    tx_rate: str | None = None
    duration_seconds: int | None = None


class SessionService:
    def __init__(self, config: AppConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner()

    def control_socket(self) -> str:
        configured_socket = self.config.generated_path("occtl.sock")
        if configured_socket.is_socket():
            return str(configured_socket)
        sockets = [
            path
            for path in self.config.system.generated_dir.glob("occtl.sock*")
            if path.is_socket()
        ]
        if sockets:
            newest = max(sockets, key=lambda path: path.stat().st_mtime)
            return str(newest)
        return str(configured_socket)

    def occtl_argv(self, *args: str) -> list[str]:
        return ["occtl", "-s", self.control_socket(), *args]

    def occtl_json_argv(self, *args: str) -> list[str]:
        return ["occtl", "--json", "-s", self.control_socket(), *args]

    def parse_sessions(self, output: str) -> list[SessionRecord]:
        table_records = self._parse_table_sessions(output, generic_ip_is="real_ip")
        if table_records:
            return table_records
        block_records = self._parse_block_sessions(output)
        if block_records:
            return block_records
        return self._parse_loose_user_rows(output)

    def parse_json_sessions(
        self,
        output: str,
        *,
        default_username: str | None = None,
    ) -> list[SessionRecord]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        items = payload if isinstance(payload, list) else [payload]
        records: list[SessionRecord] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            record = self._session_from_json_item(item, default_username=default_username)
            if record is not None:
                records.append(record)
        return records

    def _session_from_json_item(
        self,
        item: dict[str, Any],
        *,
        default_username: str | None = None,
    ) -> SessionRecord | None:
        normalized = {
            self._normalize_header(str(key)): value
            for key, value in item.items()
            if value is not None
        }
        username = self._first_json_value(
            normalized,
            "username",
            "user",
            "name",
            "login",
        ) or default_username
        if not username:
            return None
        # device (e.g. "oc-client0") and the connection timestamp are
        # unrelated: device is purely for display, the timestamp is purely
        # for computing duration_seconds. Neither substitutes for the other.
        device = self._first_json_value(normalized, "device")
        connected_since = self._first_json_value(
            normalized,
            "session_started_at",
            "last_connected_at",
            "connected_since",
            "connected_at",
            "connected_time",
            "connected",
            "connected_for",
            "connection_time",
            "connect_time",
            "since",
            "session_time",
            "login_since",
            "login_time",
            "logged_in_since",
            "time",
        )
        # occtl prints both "Session started at" (absolute date) and
        # "_Session started at" (elapsed, e.g. " 3days"); normalization
        # collapses the two into one key with the elapsed string winning, so
        # connected_since may hold either form. The raw_* epoch fields are
        # unambiguous — prefer them and fall back to string parsing.
        duration_seconds: int | None = None
        for epoch_key in ("raw_session_started_at", "raw_connected_at"):
            duration_seconds = self._duration_from_epoch(normalized.get(epoch_key))
            if duration_seconds is not None:
                break
        if duration_seconds is None:
            duration_seconds = self._parse_duration_seconds(connected_since)
        rx = self._first_json_value(normalized, "rx", "download", "downloaded", "received")
        tx = self._first_json_value(normalized, "tx", "upload", "uploaded", "sent", "transmitted")
        raw_rx = self._first_json_value(normalized, "raw_rx", "bytes_in")
        raw_tx = self._first_json_value(normalized, "raw_tx", "bytes_out")
        rx_rate = self._first_json_value(
            normalized,
            "average_rx",
            "rx_rate",
            "download_rate",
            "received_rate",
        )
        tx_rate = self._first_json_value(
            normalized,
            "average_tx",
            "tx_rate",
            "upload_rate",
            "sent_rate",
        )
        return SessionRecord(
            username=username,
            vpn_ip=self._first_json_value(
                normalized,
                "vpn_ip",
                "assigned_ip",
                "assigned_address",
                "local_ip",
                "ipv4",
                "ip",
            ),
            real_ip=self._first_json_value(
                normalized,
                "real_ip",
                "remote_ip",
                "remote_address",
                "peer_ip",
                "source_ip",
            ),
            device=device,
            rx=rx or self._format_raw_bytes(raw_rx),
            tx=tx or self._format_raw_bytes(raw_tx),
            rx_rate=rx_rate,
            tx_rate=tx_rate,
            duration_seconds=duration_seconds,
        )

    @staticmethod
    def _first_json_value(row: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = row.get(key)
            if value is None or value == "":
                continue
            if isinstance(value, bool):
                return "true" if value else "false"
            return str(value)
        return None

    @staticmethod
    def _format_raw_bytes(value: str | None) -> str | None:
        if value is None:
            return None
        try:
            amount = int(value)
        except ValueError:
            return value
        return f"{amount} bytes"

    @staticmethod
    def _field_patterns() -> dict[str, str]:
        return {
            "vpn_ip": (
                r"^(?:vpn(?:[-_\s]*ip)?|assigned(?:[-_\s]*(?:ip|address))?|"
                r"local(?:[-_\s]*(?:ip|address))?|ipv4(?:[-_\s]*(?:ip|address))?|"
                r"ip)\s*[:=]\s*(\S+)"
            ),
            "real_ip": (
                r"^(?:real|remote|peer|source|external|public)"
                r"(?:[-_\s]*(?:ip|address|addr))?\s*[:=]\s*(\S+)"
            ),
            "device": r"^device\s*[:=]\s*(\S+)",
            "connected_since": (
                r"^(?:last[-_\s]*connected(?:[-_\s]*at)?|"
                r"session[-_\s]*started(?:[-_\s]*at)?|"
                r"connected(?:[-_\s]*(?:at|since))?|since)\s*[:=]\s*"
                r"(.+?)(?=\s+\b(?:RX|TX|Download|Upload)\s*[:=]|$)"
            ),
            "rx": r"^(?:rx|download|downloaded|received|bytes[-_\s]*in)\s*[:=]\s*(.+)$",
            "tx": r"^(?:tx|upload|uploaded|sent|transmitted|bytes[-_\s]*out)\s*[:=]\s*(.+)$",
            "rx_rate": r"^(?:average[-_\s]*rx|rx[-_\s]*rate)\s*[:=]\s*(.+)$",
            "tx_rate": r"^(?:average[-_\s]*tx|tx[-_\s]*rate)\s*[:=]\s*(.+)$",
        }

    def _parse_table_sessions(
        self,
        output: str,
        *,
        generic_ip_is: str = "vpn_ip",
    ) -> list[SessionRecord]:
        lines = [line.rstrip() for line in output.splitlines() if line.strip()]
        if len(lines) < 2:
            return []
        header_index = next(
            (
                index
                for index, line in enumerate(lines)
                if re.search(r"\b(user|username)\b", line, re.IGNORECASE)
                and re.search(r"\b(ip|remote|real|rx|tx|download|upload)\b", line, re.IGNORECASE)
            ),
            None,
        )
        if header_index is None:
            return []
        headers = self._split_table_row(lines[header_index])
        if len(headers) < 2:
            return []
        records: list[SessionRecord] = []
        for line in lines[header_index + 1 :]:
            if set(line.strip()) <= {"-", "+", " "}:
                continue
            values = self._split_table_row(line)
            if len(values) < 2:
                continue
            row = {
                self._normalize_header(header): values[index].strip()
                for index, header in enumerate(headers)
                if index < len(values)
            }
            username = self._first_value(row, "username", "user")
            if not username:
                continue
            # occtl's plain-text summary table labels this column "Connected",
            # but its content is either a device/interface name (e.g. "vpns0")
            # or an elapsed-time string (e.g. "00:03:21") depending on occtl
            # version - never both. Classify it instead of showing one as the
            # other.
            raw_connected = self._first_value(
                row, "device", "connected", "connected_since", "since"
            )
            duration_seconds = self._parse_duration_seconds(raw_connected)
            device = None if duration_seconds is not None else raw_connected
            vpn_keys = ["vpn_ip", "assigned_ip", "local_ip", "ipv4"]
            real_keys = ["real_ip", "remote_ip", "peer_ip", "source_ip", "ip"]
            if generic_ip_is == "vpn_ip":
                vpn_keys.append("ip")
                real_keys.remove("ip")
            records.append(
                SessionRecord(
                    username=username,
                    vpn_ip=self._first_value(row, *vpn_keys),
                    real_ip=self._first_value(row, *real_keys),
                    device=device,
                    rx=self._first_value(row, "rx", "download", "downloaded", "received"),
                    tx=self._first_value(row, "tx", "upload", "uploaded", "sent", "transmitted"),
                    duration_seconds=duration_seconds,
                )
            )
        return records

    @staticmethod
    def _split_table_row(line: str) -> list[str]:
        parts = re.split(r"\s{2,}|\t+", line.strip())
        if len(parts) > 1:
            return parts
        return line.split()

    @staticmethod
    def _normalize_header(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")

    @staticmethod
    def _first_value(row: dict[str, str], *keys: str) -> str | None:
        for key in keys:
            value = row.get(key)
            if value and value != "-":
                return value
        return None

    def _parse_loose_user_rows(self, output: str) -> list[SessionRecord]:
        records: list[SessionRecord] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or ":" in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            username = parts[0].strip()
            if not self._looks_like_username(username):
                continue
            ips = [
                token
                for part in parts[1:]
                if (token := part.strip("[](),;")) and self._is_ip(token)
            ]
            vpn_ip, real_ip = self._split_loose_ips(ips)
            connected_since = self._loose_connected_value(parts[1:])
            records.append(
                SessionRecord(
                    username=username,
                    vpn_ip=vpn_ip,
                    real_ip=real_ip,
                    duration_seconds=self._parse_duration_seconds(connected_since),
                )
            )
        return records

    @staticmethod
    def _looks_like_username(value: str) -> bool:
        lowered = value.lower()
        if lowered in {
            "user",
            "username",
            "id",
            "sid",
            "session",
            "sessions",
            "cookie",
            "no",
        }:
            return False
        if SessionService._is_ip(value):
            return False
        return re.match(r"^[A-Za-z0-9_.@-]{1,128}$", value) is not None

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True

    def _split_loose_ips(self, ips: list[str]) -> tuple[str | None, str | None]:
        vpn_network = ipaddress.ip_network(self.config.server.ipv4_network, strict=False)
        vpn_ip: str | None = None
        real_ip: str | None = None
        for value in ips:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if vpn_ip is None:
                try:
                    if address in vpn_network:
                        vpn_ip = value
                        continue
                except TypeError:
                    pass
            if real_ip is None:
                real_ip = value
        return vpn_ip, real_ip

    @staticmethod
    def _loose_connected_value(parts: list[str]) -> str | None:
        for index, part in enumerate(parts):
            if re.match(r"^\d{4}-\d{2}-\d{2}$", part):
                tail = parts[index : index + 2]
                return " ".join(tail)
            if re.match(r"^\d+(?:s|m|h|d)$", part, re.IGNORECASE):
                return part
            if re.match(r"^\d{1,2}:\d{2}(?::\d{2})?$", part):
                return part
        return None

    def list_sessions(self) -> list[SessionRecord]:
        json_result = self.runner.run(
            self.occtl_json_argv("show", "users"),
            timeout=30,
            check=False,
        )
        if json_result.ok:
            json_sessions = self._enrich_sessions(self.parse_json_sessions(json_result.stdout))
            if json_sessions:
                return self._fill_missing_session_details(json_sessions)
        result = self.runner.run(self.occtl_argv("show", "users"), timeout=30, check=False)
        if not result.ok:
            return []
        sessions = self._enrich_sessions(self.parse_sessions(result.stdout))
        if sessions:
            return self._fill_missing_session_details(sessions)
        return self._list_sessions_from_session_ids()

    @staticmethod
    def _duration_from_tokens(text: str) -> int | None:
        matches = _DURATION_TOKEN_RE.findall(text)
        if not matches:
            return None
        return sum(
            int(value) * _DURATION_UNIT_SECONDS[unit[0].lower()] for value, unit in matches
        )

    # ocserv reports conn_time/session_start_time of 0 when unknown; anything
    # before this cutoff (2000-01-01) is such a placeholder, not a real start.
    _MIN_EPOCH = 946684800

    @classmethod
    def _duration_from_epoch(cls, value: Any) -> int | None:
        if value is None:
            return None
        try:
            epoch = int(float(str(value)))
        except ValueError:
            return None
        if epoch < cls._MIN_EPOCH:
            return None
        elapsed = int(datetime.datetime.now().timestamp()) - epoch
        return elapsed if elapsed >= 0 else None

    @classmethod
    def _parse_duration_seconds(cls, connected: str | None) -> int | None:
        if not connected:
            return None
        text = connected.strip()

        # occtl's own "(32s)"/"(1h2m)" suffix is authoritative when present.
        paren_match = _PAREN_RE.search(text)
        if paren_match:
            duration = cls._duration_from_tokens(paren_match.group(1))
            if duration is not None:
                return duration

        # An absolute "Connected since" timestamp: derive elapsed time from now.
        abs_match = _ABS_DATETIME_RE.search(text)
        if abs_match:
            date_part, time_part = abs_match.groups()
            parsed: datetime.datetime | None = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    parsed = datetime.datetime.strptime(f"{date_part} {time_part}", fmt)
                    break
                except ValueError:
                    continue
            if parsed is not None:
                elapsed = (datetime.datetime.now() - parsed).total_seconds()
                if elapsed >= 0:
                    return int(elapsed)

        # A bare compact duration, e.g. "32s" or "1h2m" from a table/loose row.
        duration = cls._duration_from_tokens(text)
        if duration is not None:
            return duration

        # occtl's plain-text "show users" table reports elapsed time as HH:MM:SS.
        hhmmss_match = _HHMMSS_RE.match(text)
        if hhmmss_match:
            hours, minutes, seconds = hhmmss_match.groups()
            return int(hours) * 3600 + int(minutes) * 60 + int(seconds or 0)

        return None

    def _fill_missing_session_details(self, sessions: list[SessionRecord]) -> list[SessionRecord]:
        if not any(self._needs_session_detail(session) for session in sessions):
            return sessions
        details = self._list_sessions_from_session_ids()
        if not details:
            return sessions
        return [
            self._merge_session_detail(session, self._best_detail(session, details))
            for session in sessions
        ]

    @staticmethod
    def _needs_session_detail(session: SessionRecord) -> bool:
        return (
            session.device is None
            or session.vpn_ip is None
            or session.rx is None
            or session.tx is None
            or session.duration_seconds is None
        )

    @staticmethod
    def _best_detail(session: SessionRecord, details: list[SessionRecord]) -> SessionRecord:
        for detail in details:
            if detail.username != session.username:
                continue
            if session.vpn_ip and detail.vpn_ip == session.vpn_ip:
                return detail
            if session.real_ip and detail.real_ip == session.real_ip:
                return detail
        for detail in details:
            if detail.username == session.username:
                return detail
        return SessionRecord(username=session.username)

    def _list_sessions_from_session_ids(self) -> list[SessionRecord]:
        json_result = self.runner.run(
            self.occtl_json_argv("show", "sessions", "all"),
            timeout=30,
            check=False,
        )
        if json_result.ok:
            json_sessions = self._list_json_session_ids(json_result.stdout)
            if json_sessions:
                return json_sessions
        result = self.runner.run(
            self.occtl_argv("show", "sessions", "all"),
            timeout=30,
            check=False,
        )
        if not result.ok:
            result = self.runner.run(
                self.occtl_argv("show", "sessions", "valid"),
                timeout=30,
                check=False,
            )
        if not result.ok:
            return []
        sessions: list[SessionRecord] = []
        for session_id in self._parse_session_ids(result.stdout):
            detail = self.runner.run(
                self.occtl_argv("show", "session", session_id),
                timeout=30,
                check=False,
            )
            if not detail.ok:
                continue
            sessions.extend(self._parse_detail_sessions(detail.stdout))
        return sessions

    def _list_json_session_ids(self, output: str) -> list[SessionRecord]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        items = payload if isinstance(payload, list) else [payload]
        sessions: list[SessionRecord] = []
        for item in items:
            session_id: str | None = None
            if isinstance(item, str):
                session_id = item
            elif isinstance(item, dict):
                normalized = {
                    self._normalize_header(str(key)): value
                    for key, value in item.items()
                    if value is not None
                }
                session_id = self._first_json_value(
                    normalized,
                    "sid",
                    "id",
                    "session_id",
                    "session",
                    "cookie",
                )
            if not session_id:
                continue
            detail = self.runner.run(
                self.occtl_json_argv("show", "session", session_id),
                timeout=30,
                check=False,
            )
            if detail.ok:
                sessions.extend(self.parse_json_sessions(detail.stdout))
                continue
            text_detail = self.runner.run(
                self.occtl_argv("show", "session", session_id),
                timeout=30,
                check=False,
            )
            if text_detail.ok:
                sessions.extend(self._parse_detail_sessions(text_detail.stdout))
        return sessions

    @staticmethod
    def _parse_session_ids(output: str) -> list[str]:
        ids: list[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(("id", "session", "cookie")):
                continue
            token = stripped.split()[0]
            if re.match(r"^[A-Za-z0-9_.:-]+$", token):
                ids.append(token)
        return ids

    def _enrich_sessions(self, sessions: list[SessionRecord]) -> list[SessionRecord]:
        enriched: list[SessionRecord] = []
        for session in sessions:
            json_result = self.runner.run(
                self.occtl_json_argv("show", "user", session.username),
                timeout=30,
                check=False,
            )
            if json_result.ok:
                details = self.parse_json_sessions(
                    json_result.stdout,
                    default_username=session.username,
                )
                detail = details[0] if details else None
                if detail is not None:
                    enriched.append(self._merge_session_detail(session, detail))
                    continue
            result = self.runner.run(
                self.occtl_argv("show", "user", session.username),
                timeout=30,
                check=False,
            )
            if not result.ok:
                enriched.append(session)
                continue
            details = self._parse_detail_sessions(result.stdout, username=session.username)
            detail = details[0] if details else None
            if detail is None:
                enriched.append(session)
                continue
            enriched.append(self._merge_session_detail(session, detail))
        return enriched

    @staticmethod
    def _merge_session_detail(
        session: SessionRecord,
        detail: SessionRecord,
    ) -> SessionRecord:
        # device and duration_seconds are computed independently at parse
        # time (see _session_from_json_item and _parse_block_sessions), so
        # each merges on its own with no cross-influence between the two.
        duration_seconds = (
            detail.duration_seconds
            if detail.duration_seconds is not None
            else session.duration_seconds
        )
        return SessionRecord(
            username=session.username,
            vpn_ip=detail.vpn_ip or session.vpn_ip,
            real_ip=detail.real_ip or session.real_ip,
            device=detail.device or session.device,
            rx=detail.rx or session.rx,
            tx=detail.tx or session.tx,
            rx_rate=detail.rx_rate or session.rx_rate,
            tx_rate=detail.tx_rate or session.tx_rate,
            duration_seconds=duration_seconds,
        )

    def _parse_detail_sessions(
        self,
        output: str,
        *,
        username: str | None = None,
    ) -> list[SessionRecord]:
        table_records = self._parse_table_sessions(output, generic_ip_is="vpn_ip")
        if table_records:
            return table_records
        return self._parse_block_sessions(output, default_username=username)

    def _parse_block_sessions(
        self,
        output: str,
        *,
        default_username: str | None = None,
    ) -> list[SessionRecord]:
        records: list[SessionRecord] = []
        current: dict[str, str] = {}

        def flush() -> None:
            username = current.get("username") or default_username
            if username and current:
                connected_since = current.get("connected_since")
                records.append(
                    SessionRecord(
                        username=username,
                        vpn_ip=current.get("vpn_ip"),
                        real_ip=current.get("real_ip"),
                        device=current.get("device"),
                        rx=current.get("rx"),
                        tx=current.get("tx"),
                        rx_rate=current.get("rx_rate"),
                        tx_rate=current.get("tx_rate"),
                        duration_seconds=self._parse_duration_seconds(connected_since),
                    )
                )

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                flush()
                current = {}
                continue
            username_match = re.search(r"^(?:username|user)\s*[:=]\s*(\S+)", line, re.IGNORECASE)
            if username_match:
                if current:
                    flush()
                    current = {}
                current["username"] = username_match.group(1)
            traffic = self._traffic_from_line(line)
            current.update(traffic)
            for key, pattern in self._field_patterns().items():
                if key in traffic:
                    continue
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    current[key] = match.group(1).strip()
        flush()
        return records

    @staticmethod
    def _traffic_from_line(line: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, label in (("rx", "RX"), ("tx", "TX")):
            match = re.search(
                rf"\b{label}\s*[:=]\s*(.+?)(?=\s+\b(?:RX|TX)\s*[:=]|$)",
                line,
                re.IGNORECASE,
            )
            if match:
                result[key] = match.group(1).strip()
        return result

    def kick(self, username: str, *, dry_run: bool = False) -> CommandResult:
        result = self.runner.run(
            self.occtl_argv("disconnect", "user", username),
            timeout=30,
            check=False,
            dry_run=dry_run,
        )
        if result.ok or dry_run:
            return result
        # occtl cannot always disconnect by name (e.g. half-open connections
        # that finished TLS but never established a full session); fall back
        # to disconnecting each of the user's workers by ID.
        worker_ids = self._worker_ids_for(username)
        if not worker_ids:
            note = (
                "no active worker found for this session; half-open connections "
                "expire on their own (auth-timeout/cookie-timeout)"
            )
            stderr = f"{result.stderr.strip()}\n{note}" if result.stderr.strip() else note
            return CommandResult(result.argv, result.returncode, result.stdout, stderr)
        id_results = [
            self.runner.run(
                self.occtl_argv("disconnect", "id", worker_id),
                timeout=30,
                check=False,
            )
            for worker_id in worker_ids
        ]
        stdout = "\n".join(item.stdout.strip() for item in id_results if item.stdout.strip())
        stderr = "\n".join(item.stderr.strip() for item in id_results if item.stderr.strip())
        returncode = 0 if any(item.ok for item in id_results) else id_results[0].returncode
        return CommandResult(
            ("occtl", "disconnect", "id", *worker_ids),
            returncode,
            stdout,
            stderr,
        )

    def _worker_ids_for(self, username: str) -> list[str]:
        result = self.runner.run(
            self.occtl_json_argv("show", "users"),
            timeout=30,
            check=False,
        )
        if not result.ok:
            return []
        try:
            loaded = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(loaded, list):
            return []
        worker_ids: list[str] = []
        for row in loaded:
            if not isinstance(row, dict):
                continue
            normalized = {
                self._normalize_header(str(key)): value
                for key, value in row.items()
                if value is not None
            }
            row_username = self._first_json_value(normalized, "username", "user")
            if row_username != username:
                continue
            worker_id = self._first_json_value(normalized, "id")
            if worker_id and worker_id not in worker_ids:
                worker_ids.append(worker_id)
        return worker_ids

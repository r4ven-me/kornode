from __future__ import annotations

import base64
import socket
import xmlrpc.client
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

# Shared with templates/supervisor.conf.j2 (passed in via SupervisorConfigRenderer)
# so the unix_http_server/supervisorctl credentials and this RPC client never drift.
RPC_USERNAME = "kornodectl"
RPC_PASSWORD = "kornodectl-local"

_RPC_TIMEOUT = 10.0


class SupervisorRpcError(RuntimeError):
    pass


class _UnixStreamHTTPConnection(HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


class _UnixStreamTransport(xmlrpc.client.Transport):
    def __init__(self, socket_path: str, timeout: float, username: str, password: str) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._timeout = timeout
        # xmlrpc.client.Transport does not extract Basic Auth from a
        # user:pass@host URI on its own; the header has to be set explicitly.
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._extra_headers = [("Authorization", f"Basic {credentials}")]

    def make_connection(
        self, host: tuple[str, dict[str, str]] | str
    ) -> _UnixStreamHTTPConnection:
        return _UnixStreamHTTPConnection(self._socket_path, self._timeout)


class SupervisorRpcClient:
    def __init__(self, socket_path: Path, timeout: float = _RPC_TIMEOUT) -> None:
        transport = _UnixStreamTransport(str(socket_path), timeout, RPC_USERNAME, RPC_PASSWORD)
        self._proxy = xmlrpc.client.ServerProxy(
            "http://localhost/RPC2", transport=transport, allow_none=True
        )

    def _call(self, method: str, *args: Any) -> Any:
        try:
            return getattr(self._proxy.supervisor, method)(*args)
        except xmlrpc.client.Fault as exc:
            raise SupervisorRpcError(f"{exc.faultString} ({method})") from exc
        except (OSError, xmlrpc.client.ProtocolError) as exc:
            raise SupervisorRpcError(f"cannot reach supervisord: {exc}") from exc

    def start_process(self, name: str) -> None:
        self._call("startProcess", name)

    def stop_process(self, name: str) -> None:
        self._call("stopProcess", name)

    def signal_process(self, name: str, signal_name: str) -> None:
        self._call("signalProcess", name, signal_name)

    def get_process_info(self, name: str) -> dict[str, Any]:
        return dict(self._call("getProcessInfo", name))

    def get_all_process_info(self) -> list[dict[str, Any]]:
        return list(self._call("getAllProcessInfo"))

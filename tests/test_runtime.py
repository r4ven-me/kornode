from __future__ import annotations

import socket
from pathlib import Path

from kornode.main import unlink_stale_runtime_sockets


def bind_unix_socket(path: Path) -> socket.socket:
    unix_socket = socket.socket(socket.AF_UNIX)
    unix_socket.bind(str(path))
    return unix_socket


def test_unlink_stale_runtime_sockets_removes_only_socket_files(tmp_path: Path) -> None:
    ocserv_socket = bind_unix_socket(tmp_path / "ocserv.sock.old")
    occtl_socket = bind_unix_socket(tmp_path / "occtl.sock")
    supervisor_socket = bind_unix_socket(tmp_path / "supervisor.sock")
    regular_file = tmp_path / "ocserv.sock.note"
    regular_file.write_text("not a socket\n", encoding="utf-8")

    try:
        unlink_stale_runtime_sockets(tmp_path)
    finally:
        ocserv_socket.close()
        occtl_socket.close()
        supervisor_socket.close()

    assert not (tmp_path / "ocserv.sock.old").exists()
    assert not (tmp_path / "occtl.sock").exists()
    assert not (tmp_path / "supervisor.sock").exists()
    assert regular_file.exists()

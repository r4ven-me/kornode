from __future__ import annotations

import stat

from kornode.services.files import FileManager


def test_atomic_write_text_preserves_existing_parent_mode(tmp_path) -> None:
    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)

    FileManager().atomic_write_text(directory / "token", "value", mode=0o600)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "token").stat().st_mode) == 0o600


def test_atomic_write_bytes_writes_binary_content_privately(tmp_path) -> None:
    target = tmp_path / "secrets" / "bundle.p12"

    FileManager().atomic_write_bytes(target, b"\x00\x01\xff\xfe")

    assert target.read_bytes() == b"\x00\x01\xff\xfe"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

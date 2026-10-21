"""The user-facing docs describe v2 only: removed v1 routing keys and commands must not reappear."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    "README.md",
    "docs/architecture.md",
    "docs/networking.md",
    "docs/features.md",
    "docs/configuration.md",
)
REMOVED_TERMS = (
    "client_policy",
    "host_policy",
    "host_split",
    r"routing\.fwmark",
    r"routing\.table_id",
    "korctl routes",
    "korctl nft",
    "korctl upstream sync",
    "upstream hook",
    "route_host_enabled",
    "accept_server_routes",
    "sync_url",
    "nft_prefix",
    "RoutingService",
    "external_lists",
    "upstream_pushed",
)
REMOVED = re.compile("|".join(REMOVED_TERMS))


@pytest.mark.parametrize("name", DOCS)
def test_doc_has_no_removed_v1_terms(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8")
    assert REMOVED.findall(text) == []

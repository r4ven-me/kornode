from __future__ import annotations

import re

CLIENTS_GROUP = "clients"
AGENTS_GROUP = "agents"
ENROLL_GROUP = "enroll"
RESERVED_GROUPS = frozenset({AGENTS_GROUP, ENROLL_GROUP})
AGENT_USER_RE = re.compile(r"^agent-[0-9]+$", re.IGNORECASE)
ENROLL_USER_PREFIX = "enroll-"
ENROLL_USER_RE = re.compile(r"enroll-[0-9]{1,3}-[A-Za-z0-9]{4,32}")


def is_reserved_username(name: str) -> bool:
    lowered = name.lower()
    return AGENT_USER_RE.match(name) is not None or lowered.startswith(ENROLL_USER_PREFIX)

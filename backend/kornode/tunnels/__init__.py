"""openconnect dialing pieces shared by the hub and the agent.

Pure helpers only: no hub config, services or renderers are imported here
(enforced by tests/test_tunnels_imports.py).
"""

from __future__ import annotations

from pathlib import Path

VPNC_SCRIPT_NAME = "vpnc-script-kornode"


def vpnc_script_source() -> Path:
    """The shipped interface-only vpnc-script."""
    return Path(__file__).with_name(VPNC_SCRIPT_NAME)

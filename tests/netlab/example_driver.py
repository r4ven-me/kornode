"""Runs inside a netlab namespace (as root): compile the hub policy of an example config
with the real `HubNetInputs`, converge the real kernel and print the leftover plan.

Usage: example_driver.py CONFIG.yaml   -> {"interfaces": [...], "after": [...]}
       example_driver.py CONFIG.yaml --interfaces  -> only the interfaces the config names
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.net.compile import compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.services.netinputs import HubNetInputs


def load(path: Path) -> AppConfig:
    names = set(re.findall(r"\$\{SECRET:([A-Za-z0-9_]+)\}", path.read_text(encoding="utf-8")))
    environ = {name: "x" for name in names} | {f"KORNODE_SECRET_{name}": "x" for name in names}
    return load_config(path, environ=environ)


def interfaces(config: AppConfig) -> list[str]:
    names = [source.interface for source in config.egress_policy().sources]
    if config.upstream.enabled:
        names += [config.upstream.profile_interface(p) for p in config.upstream.profiles]
    return sorted(set(names))


def main() -> None:
    config = load(Path(sys.argv[1]))
    if "--state-dir" in sys.argv:
        root = Path(sys.argv[sys.argv.index("--state-dir") + 1])
        config.system.data_dir = root / "data"
        config.system.generated_dir = root / "generated"
        config.system.secrets_dir = root / "secrets"
        config.system.log_dir = root / "logs"
    if "--interfaces" in sys.argv:
        print(json.dumps(interfaces(config)))
        return
    inputs = HubNetInputs(config)
    want = compile_policy(inputs.policy(), inputs.facts()).desired
    kernel = Kernel()
    keys = [sysctl.key for sysctl in want.sysctls]
    chains = sorted({rule.chain_key for rule in want.foreign_rules})
    devs = sorted({address.dev for address in want.addresses})  # like the reconciler
    kernel.apply(diff(kernel.read(keys, chains, devs), want))
    left = diff(kernel.read(keys, chains, devs), want)
    print(json.dumps({"after": [repr(op) for op in left.ops]}))


if __name__ == "__main__":
    main()

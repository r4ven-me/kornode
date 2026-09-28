from __future__ import annotations

import http.client
import ssl

from kornode.config.loader import load_config


def check() -> bool:
    config = load_config()
    if not config.web.enabled:
        if not config.server.enabled:
            return True
        return config.generated_path("occtl.sock").is_socket() or any(
            path.is_socket() for path in config.system.generated_dir.glob("ocserv.sock*")
        )

    # web.listen may be bound to a specific address (e.g. behind a reverse
    # proxy on a loopback alias like 127.207.207.1, not 127.0.0.1 itself) --
    # connecting to a hardcoded 127.0.0.1 would then never reach it. "0.0.0.0"
    # (bind-all) is the one case that still needs the 127.0.0.1 substitution,
    # since it isn't itself a valid connect target on every platform.
    host = config.web.listen if config.web.listen not in ("0.0.0.0", "::") else "127.0.0.1"
    try:
        if config.web.tls:
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                host,
                config.web.port,
                timeout=5,
                context=ssl._create_unverified_context(),
            )
        else:
            connection = http.client.HTTPConnection(host, config.web.port, timeout=5)
        connection.request("GET", "/healthz")
        return connection.getresponse().status == 200
    except OSError:
        return False


def main() -> None:
    raise SystemExit(0 if check() else 1)


if __name__ == "__main__":
    main()

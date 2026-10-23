"""httpx client of the hub control API (spec 05, mTLS, pinned CA)."""

from __future__ import annotations

import base64
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

API = "/agent/v1"


class HubUnreachable(RuntimeError):
    """Network-level failure: the hub or the path to it is down."""


class ControlError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message

    @property
    def revoked(self) -> bool:
        return self.code == "revoked"


@dataclass(frozen=True)
class BundlePayload:
    version: int
    body: bytes
    signature: str


@dataclass(frozen=True)
class Command:
    id: str
    type: str
    args: dict[str, Any]
    expires_at: str


@dataclass(frozen=True)
class PollResult:
    bundle: BundlePayload | None
    commands: list[Command]


def _bundle(raw: dict[str, Any]) -> BundlePayload:
    return BundlePayload(
        version=int(raw["version"]),
        body=base64.b64decode(raw["body_b64"], validate=True),
        signature=str(raw["signature"]),
    )


def mtls_context(tls_dir: Path) -> ssl.SSLContext:
    """Verify the hub against the enrolled CA only; present the agent certificate."""
    context = ssl.create_default_context(cafile=str(tls_dir / "ca.pem"))
    context.load_cert_chain(str(tls_dir / "cert.pem"), str(tls_dir / "key.pem"))
    return context


class ControlClient:
    def __init__(
        self,
        control_url: str,
        *,
        ssl_context: ssl.SSLContext | bool,
        timeout: float = 10.0,
        local_address: Callable[[], str | None] = lambda: None,
    ) -> None:
        self._base = control_url.rstrip("/") + API
        self._ssl = ssl_context
        self._timeout = timeout
        self._local_address = local_address
        self._bound: str | None = None
        self._http = self._build(None)

    def _build(self, address: str | None) -> httpx.AsyncClient:
        # Traffic to the hub is marked into the interlink exit, which does not
        # NAT: it must leave with the agent's interlink address as its source.
        transport = httpx.AsyncHTTPTransport(verify=self._ssl, local_address=address)
        return httpx.AsyncClient(base_url=self._base, transport=transport, timeout=self._timeout)

    @classmethod
    def enrolled(
        cls,
        control_url: str,
        tls_dir: Path,
        local_address: Callable[[], str | None] = lambda: None,
    ) -> ControlClient:
        return cls(control_url, ssl_context=mtls_context(tls_dir), local_address=local_address)

    @classmethod
    def for_enroll(cls, control_url: str) -> ControlClient:
        # Before enrollment the agent has no CA. The request travels inside
        # the enroll openconnect session, whose server certificate is pinned
        # (D-53); the CA arrives in the response.
        return cls(control_url, ssl_context=False)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(
        self, method: str, path: str, *, timeout: float | None = None, **kwargs: Any
    ) -> httpx.Response:
        address = self._local_address()
        if address != self._bound:
            old, self._http, self._bound = self._http, self._build(address), address
            await old.aclose()
        try:
            response = await self._http.request(
                method,
                path,
                timeout=httpx.Timeout(timeout or self._timeout, connect=self._timeout),
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise HubUnreachable(str(exc) or type(exc).__name__) from exc
        if response.status_code >= 400:
            try:
                data = response.json()
                code, message = str(data["error"]), str(data.get("message", ""))
            except (ValueError, KeyError, TypeError):
                code, message = "internal", response.text[:200]
            raise ControlError(response.status_code, code, message)
        return response

    async def ping(self) -> None:
        await self._request("GET", "/ping")

    async def poll(self, since: int, wait: float) -> PollResult:
        response = await self._request(
            "GET", "/poll", params={"since": since, "wait": wait}, timeout=wait + 15
        )
        data = response.json()
        commands = [
            Command(str(c["id"]), str(c["type"]), dict(c.get("args") or {}), str(c["expires_at"]))
            for c in data.get("commands", [])
        ]
        return PollResult(_bundle(data["bundle"]) if data.get("bundle") else None, commands)

    async def report(self, body: dict[str, Any]) -> None:
        await self._request("POST", "/report", json=body)

    async def command_result(
        self, command_id: str, *, ok: bool, output: str, artefact: bytes | None = None
    ) -> None:
        payload: dict[str, Any] = {"ok": ok, "output": output}
        if artefact is not None:
            payload["artefact_b64"] = base64.b64encode(artefact).decode("ascii")
        await self._request("POST", f"/commands/{command_id}/result", json=payload, timeout=60)

    async def renew(self, csr_pem: str) -> str:
        response = await self._request("POST", "/renew", json={"csr_pem": csr_pem})
        return str(response.json()["cert_pem"])

    async def enroll(
        self,
        *,
        token_id: str,
        secret: str,
        csr_pem: str,
        seal_pubkey_b64: str,
        facts: dict[str, Any],
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            "/enroll",
            json={
                "token_id": token_id,
                "secret": secret,
                "csr_pem": csr_pem,
                "seal_pubkey_b64": seal_pubkey_b64,
                "facts": facts,
            },
        )
        data: dict[str, Any] = response.json()
        return data


def decode_enroll_bundle(result: dict[str, Any]) -> BundlePayload | None:
    raw = result.get("bundle")
    return _bundle(raw) if raw else None

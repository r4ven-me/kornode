from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_mutation, apply_config_patch
from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.services.config_collections import raw_collection, raw_config_value, replace_named
from kornode.services.secrets import is_secret_key
from kornode.services.upstream import UpstreamService
from kornode.tunnels.pin import fetch_server_pin

# cert_file_base64/key_file_base64 are base64-encoded certificate/key
# material pasted by the admin -- their names don't match any of
# is_secret_key()'s patterns (password/token/secret/etc.) at all, so they
# need an explicit override alongside it. camouflage_secret DOES match
# is_secret_key() (see services.secrets._TEXT_ONLY_NON_SECRET_KEYS for why
# it's exempt only from the *rendered ocserv.conf directive* masking, not
# this structured one) and needs no separate entry here.
_ALWAYS_MASK_PROFILE_FIELDS = {"cert_file_base64", "key_file_base64"}

router = APIRouter(dependencies=[Depends(require_admin)])


class SwitchRequest(BaseModel):
    profile: str


class DryRunRequest(BaseModel):
    dry_run: bool = False


class ProfileEnabledRequest(BaseModel):
    enabled: bool


class UpstreamSettingsRequest(BaseModel):
    enabled: bool
    interface: str | None = None
    active_profile: str | None = None
    check_interval: int | None = None
    check_threshold: int | None = None
    check_settle_seconds: int | None = None
    failover: bool | None = None
    connect_on_boot: bool | None = None


class FetchPinRequest(BaseModel):
    server: str = Field(min_length=1)
    port: int = Field(default=443, ge=1, le=65535)


class UpstreamProfileRequest(BaseModel):
    name: str
    kind: Literal["openconnect", "external_interface"] = "openconnect"
    server: str | None = None
    port: str = "443"
    interface: str | None = None
    auth_type: Literal["password", "cert", "p12"] = "password"
    trusted_cert: bool = False
    username: str | None = None
    password: str | None = None
    cert_file: str | None = None
    cert_file_base64: str | None = None
    key_file: str | None = None
    key_file_base64: str | None = None
    cert_pass: str | None = None
    server_cert_pin: str | None = None
    check_host: str | None = None
    camouflage_secret: str | None = None
    # Per-profile: whether the watchdog should keep this profile dialed at
    # all (UpstreamProfileConfig.enabled). Saving a profile never touches the
    # global upstream.enabled toggle -- that one is only changed through
    # POST /api/upstream/settings, so editing a profile can't take down the
    # tunnels (and with them the panel, when it is only reachable over one).
    enabled: bool = True


@router.get("")
def list_profiles(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [_safe_profile_dump(profile) for profile in UpstreamService(config).list_profiles()]


@router.get("/status")
def status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return UpstreamService(config).status().__dict__


@router.post("/switch")
def switch_profile(
    request: Request,
    payload: SwitchRequest,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    UpstreamService(config).switch_profile(payload.profile)
    apply_config_patch(request, {"upstream": {"active_profile": payload.profile}})
    return {"status": "switched"}


@router.post("/settings")
def save_settings(
    request: Request,
    payload: UpstreamSettingsRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    patch: dict[str, object] = {"enabled": payload.enabled}
    if payload.interface is not None:
        patch["interface"] = payload.interface
    if payload.active_profile is not None:
        patch["active_profile"] = payload.active_profile
    elif config.upstream.active_profile is not None:
        patch["active_profile"] = config.upstream.active_profile
    if payload.check_interval is not None:
        patch["check_interval"] = payload.check_interval
    if payload.check_threshold is not None:
        patch["check_threshold"] = payload.check_threshold
    if payload.check_settle_seconds is not None:
        patch["check_settle_seconds"] = payload.check_settle_seconds
    if payload.failover is not None:
        patch["failover"] = payload.failover
    if payload.connect_on_boot is not None:
        patch["connect_on_boot"] = payload.connect_on_boot
    loaded_config, written = apply_config_patch(request, {"upstream": patch})
    # Reuse _safe_profile_dump() per profile instead of this endpoint's own
    # exclude set: that set never included camouflage_secret, leaking it in
    # plaintext here even after routes_upstream.py's other endpoints were
    # fixed to mask it.
    upstream_data = loaded_config.upstream.model_dump(mode="json", exclude={"profiles"})
    upstream_data["profiles"] = [
        _safe_profile_dump(item) for item in loaded_config.upstream.profiles
    ]
    return {
        "status": "saved",
        "written": written,
        "upstream": upstream_data,
    }


@router.post("/fetch-pin")
def fetch_pin(payload: FetchPinRequest) -> dict[str, str]:
    """Show the pin of the certificate an upstream server presents right now.

    RUNTIME: connects to the server. The certificate is NOT verified -- the
    admin compares the pin with the one the upstream shows for itself
    before saving it as server_cert_pin.
    """
    try:
        pin = fetch_server_pin(payload.server.strip(), payload.port)
    except OSError as exc:
        reason = "connection failed"
        if isinstance(exc, ConnectionRefusedError):
            reason = "connection refused"
        elif isinstance(exc, TimeoutError):
            reason = "connection timed out"
        raise HTTPException(
            status_code=400, detail=f"Could not fetch server certificate: {reason}"
        ) from None
    return pin.as_dict()


@router.post("/profiles")
def save_profile(
    request: Request,
    payload: UpstreamProfileRequest,
) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        profiles = raw_collection(raw, Path(request.app.state.config_path), "upstream", "profiles")
        existing = next((item for item in profiles if item.get("name") == payload.name), {})
        data = payload.model_dump(exclude_none=True)
        for field in ("password", "cert_pass", "camouflage_secret", "interface"):
            if field not in data and field in existing:
                data[field] = existing[field]
        for path_field, base64_field in (
            ("cert_file", "cert_file_base64"),
            ("key_file", "key_file_base64"),
        ):
            if path_field not in data and base64_field not in data:
                for field in (path_field, base64_field):
                    if field in existing:
                        data[field] = existing[field]
        upstream = raw.setdefault("upstream", {})
        upstream["profiles"] = replace_named(profiles, payload.name, data)
        if (
            raw_config_value(raw, Path(request.app.state.config_path), "upstream", "active_profile")
            is None
        ):
            upstream["active_profile"] = payload.name
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {
        "status": "saved",
        "written": written,
        "profiles": [_safe_profile_dump(item) for item in loaded_config.upstream.profiles],
    }


@router.post("/profiles/{name}/enabled")
def set_profile_enabled(
    request: Request,
    name: str,
    payload: ProfileEnabledRequest,
) -> dict[str, object]:
    """Toggle whether the watchdog should keep this profile dialed at all
    (UpstreamService.enforce_profile_enablement), without resending the
    whole profile (and its secrets) the way saving from the edit form
    would."""

    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        profiles = raw_collection(raw, Path(request.app.state.config_path), "upstream", "profiles")
        existing = next((item for item in profiles if item.get("name") == name), None)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"unknown upstream profile: {name}")
        existing["enabled"] = payload.enabled
        raw.setdefault("upstream", {})["profiles"] = profiles
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {
        "status": "saved",
        "written": written,
        "profiles": [_safe_profile_dump(item) for item in loaded_config.upstream.profiles],
    }


@router.delete("/profiles/{name}")
def delete_profile(request: Request, name: str) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        profiles = raw_collection(raw, Path(request.app.state.config_path), "upstream", "profiles")
        profiles = replace_named(profiles, name, None)
        upstream = raw.setdefault("upstream", {})
        upstream["profiles"] = profiles
        if not profiles:
            upstream.update(active_profile=None, enabled=False)
        elif (
            raw_config_value(raw, Path(request.app.state.config_path), "upstream", "active_profile")
            == name
        ):
            upstream["active_profile"] = profiles[0]["name"]
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {
        "status": "deleted",
        "written": written,
        "profiles": [_safe_profile_dump(item) for item in loaded_config.upstream.profiles],
    }


def _safe_profile_dump(profile: UpstreamProfileConfig) -> dict[str, object]:
    """Mask every write-only/secret field via the centralized is_secret_key()
    check (password and cert_pass both match its generic pattern) instead
    of a hand-picked exclude set, so a *future* field with a secret-like
    name (e.g. an api_key or bind_password) is masked here automatically
    instead of silently leaking until someone remembers to add it to a list
    by hand. cert_file_base64/key_file_base64/camouflage_secret need an
    explicit override on top -- see _ALWAYS_MASK_PROFILE_FIELDS above.
    """
    data = profile.model_dump(mode="json")
    for key, value in data.items():
        if value in (None, "", False):
            continue
        if key in _ALWAYS_MASK_PROFILE_FIELDS or is_secret_key(key):
            data[key] = "***"
    return data


@router.post("/connect")
def connect_active(
    request: Request,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = UpstreamService(config).connect_active(dry_run=payload.dry_run if payload else False)
    return {
        "argv": ["korctl", "upstream", "connect"],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/disconnect")
def disconnect_active(
    request: Request,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = UpstreamService(config).disconnect(dry_run=payload.dry_run if payload else False)
    return {
        "argv": ["korctl", "upstream", "disconnect"],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/profiles/{name}/connect")
def connect_profile(
    request: Request,
    name: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = UpstreamService(config).connect(name, dry_run=payload.dry_run if payload else False)
    return {
        "argv": ["korctl", "upstream", "connect", name],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/profiles/{name}/disconnect")
def disconnect_profile(
    request: Request,
    name: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = UpstreamService(config).disconnect(name, dry_run=payload.dry_run if payload else False)
    return {
        "argv": ["korctl", "upstream", "disconnect", name],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }

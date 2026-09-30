from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.services.cert_pin import fetch_server_pin
from kornode.services.secrets import is_secret_key
from kornode.services.upstream import UpstreamService

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
    # Route these specific CIDRs/domains through this profile specifically,
    # regardless of which profile is active/default -- see
    # RoutingService.list_targets().
    route_clients_enabled: bool = True
    routes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    route_host_enabled: bool = False
    host_routes: list[str] = Field(default_factory=list)
    host_domains: list[str] = Field(default_factory=list)
    # Server-pushed host routing (UpstreamProfileConfig.accept_server_routes/
    # sync_*): the routes/split-DNS the upstream server hands this profile.
    accept_server_routes: bool = False
    sync_url: str | None = None
    sync_interval: int = 60
    sync_verify_tls: bool = False
    # Per-profile: whether the watchdog should keep this profile dialed at
    # all (UpstreamProfileConfig.enabled). Distinct from `enable` below,
    # which is the *global* upstream.enabled toggle set when saving any
    # profile from the create/edit form.
    enabled: bool = True
    # Explicit fwmark/table_id offset override (UpstreamProfileConfig.
    # routing_offset). Omitted from the request -> an existing profile keeps
    # its saved value; an explicit null clears it back to position-derived.
    routing_offset: int | None = None
    enable: bool = True


@router.get("")
def list_profiles(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [
        _safe_profile_dump(profile)
        for profile in UpstreamService(config).list_profiles()
    ]


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
        raise ValueError(
            f"could not read the certificate of {payload.server}:{payload.port}: {exc}"
        ) from exc
    return pin.as_dict()


@router.post("/profiles")
def save_profile(
    request: Request,
    payload: UpstreamProfileRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    existing = next(
        (item for item in config.upstream.profiles if item.name == payload.name), None
    )
    data = payload.model_dump(exclude={"enable"}, exclude_none=True)
    if existing:
        _preserve_unset_secret(data, existing, "password")
        _preserve_unset_secret(data, existing, "cert_pass")
        _preserve_unset_secret(data, existing, "camouflage_secret")
        _preserve_unset_file_field(data, existing, "cert_file", "cert_file_base64")
        _preserve_unset_file_field(data, existing, "key_file", "key_file_base64")
        for field in ("interface", "routing_offset"):
            if field not in payload.model_fields_set and getattr(existing, field) is not None:
                data[field] = getattr(existing, field)
    profile = UpstreamProfileConfig.model_validate(data)
    # Edit in place: a profile's tunnel interface and fwmark/table_id offset
    # are derived from its position in upstream.profiles (see
    # UpstreamConfig.profile_interface()/profile_routing_offset()), so moving
    # an edited profile to the end would silently renumber live tunnels.
    profiles = [
        profile if item.name == profile.name else item for item in config.upstream.profiles
    ]
    if existing is None:
        profiles.append(profile)
    patch: dict[str, object] = {
        "profiles": [item.model_dump(mode="json") for item in profiles],
        "enabled": payload.enable,
    }
    # Only pick a default profile automatically when there isn't one yet
    # (the very first profile ever saved). Once one is active, saving --
    # whether creating another profile or editing an existing one to add
    # its own routes/domains as a named target -- must never silently
    # switch it; that's what POST /switch is for.
    if config.upstream.active_profile is None:
        patch["active_profile"] = profile.name
    loaded_config, written = apply_config_patch(request, {"upstream": patch})
    return {
        "status": "saved",
        "written": written,
        "profiles": [
            _safe_profile_dump(item)
            for item in loaded_config.upstream.profiles
        ],
    }


@router.post("/profiles/{name}/sync")
def sync_profile(request: Request, name: str) -> dict[str, object]:
    """Pull this profile's routes/split-DNS from its upstream panel now
    (UpstreamProfileConfig.sync_url) and apply whatever changed. RUNTIME:
    network, through the profile's own tunnel."""
    config: AppConfig = request.app.state.config
    profile = next((item for item in config.upstream.profiles if item.name == name), None)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"unknown upstream profile: {name}")
    if not profile.sync_url:
        raise HTTPException(status_code=400, detail=f"profile {name!r} has no sync_url")
    service = UpstreamService(config)
    synced = service.sync_server_routes(profile)
    if synced.sync_error:
        raise HTTPException(status_code=502, detail=f"sync failed: {synced.sync_error}")
    results = service.apply_server_routing_if_changed()
    return {
        "status": "synced",
        "server_routing": service.server_routing_status(profile),
        "results": [
            {
                "argv": list(result.argv),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "dry_run": result.dry_run,
            }
            for result in results
        ],
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
    config: AppConfig = request.app.state.config
    if not any(item.name == name for item in config.upstream.profiles):
        raise HTTPException(status_code=404, detail=f"unknown upstream profile: {name}")
    profiles = [
        {**item.model_dump(mode="json"), "enabled": payload.enabled}
        if item.name == name
        else item.model_dump(mode="json")
        for item in config.upstream.profiles
    ]
    loaded_config, written = apply_config_patch(request, {"upstream": {"profiles": profiles}})
    return {
        "status": "saved",
        "written": written,
        "profiles": [_safe_profile_dump(item) for item in loaded_config.upstream.profiles],
    }


@router.delete("/profiles/{name}")
def delete_profile(request: Request, name: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    profiles = [item for item in config.upstream.profiles if item.name != name]
    patch: dict[str, object] = {"profiles": [item.model_dump(mode="json") for item in profiles]}
    if not profiles:
        patch["active_profile"] = None
        patch["enabled"] = False
    elif config.upstream.active_profile == name:
        patch["active_profile"] = profiles[0].name
    loaded_config, written = apply_config_patch(request, {"upstream": patch})
    return {
        "status": "deleted",
        "written": written,
        "profiles": [
            _safe_profile_dump(item)
            for item in loaded_config.upstream.profiles
        ],
    }


def _preserve_unset_secret(
    data: dict[str, object],
    existing: UpstreamProfileConfig,
    field: str,
) -> None:
    """Keep a write-only secret when the request omits it (editing a profile
    without retyping a value the API never sends back)."""
    if field not in data:
        value = getattr(existing, field)
        if value:
            data[field] = value


def _preserve_unset_file_field(
    data: dict[str, object],
    existing: UpstreamProfileConfig,
    path_field: str,
    base64_field: str,
) -> None:
    """Keep an existing cert/key source when the request sets neither its
    path nor its base64 variant -- both are write-only from the API's point
    of view (the path is visible, but distinguishing "cleared" from "left
    alone because it was never shown" is only possible when both are
    absent)."""
    if path_field in data or base64_field in data:
        return
    existing_path = getattr(existing, path_field)
    existing_base64 = getattr(existing, base64_field)
    if existing_path:
        data[path_field] = str(existing_path)
    elif existing_base64:
        data[base64_field] = existing_base64


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
    result = UpstreamService(config).connect_active(
        dry_run=payload.dry_run if payload else False
    )
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
    result = UpstreamService(config).disconnect(
        dry_run=payload.dry_run if payload else False
    )
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
    result = UpstreamService(config).connect(
        name, dry_run=payload.dry_run if payload else False
    )
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
    result = UpstreamService(config).disconnect(
        name, dry_run=payload.dry_run if payload else False
    )
    return {
        "argv": ["korctl", "upstream", "disconnect", name],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }

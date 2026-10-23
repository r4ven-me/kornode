from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_mutation, apply_config_patch
from kornode.api.routes_server import ocserv_apply_result, running_ocserv_conf
from kornode.config.models import AppConfig, OidcProviderConfig
from kornode.services.config_collections import raw_collection, replace_named
from kornode.services.secrets import is_secret_key
from kornode.services.server import ServerService

router = APIRouter(dependencies=[Depends(require_admin)])


class OidcAuthSettingsRequest(BaseModel):
    enabled: bool
    connector: Literal["pam", "radius"] = "pam"
    pam_service: str = "ocserv"
    pam_gid_min: int | None = Field(default=1000, ge=0)
    radius_config_file: str = "/etc/radiusclient/radiusclient.conf"
    radius_groupconfig: bool = True
    radius_nas_identifier: str | None = None
    radius_group_separator: Literal["semicolon", "comma"] = "semicolon"


class OidcProviderRequest(BaseModel):
    name: str
    issuer_url: str
    client_id: str
    client_secret: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    allowed_groups: list[str] = Field(default_factory=list)


class IdentitySettingsRequest(BaseModel):
    select_group_by_url: bool = False
    default_select_group: str | None = None
    default_group_config: str | None = None


class GroupPolicyRequest(BaseModel):
    name: str
    display_name: str | None = None
    routes: list[str] = Field(default_factory=list)
    no_routes: list[str] = Field(default_factory=list)
    dns: list[str] = Field(default_factory=list)
    split_dns: list[str] = Field(default_factory=list)
    tunnel_all_dns: bool | None = None
    max_same_clients: int | None = Field(default=None, ge=1)
    session_timeout: int | None = Field(default=None, ge=1)
    idle_timeout: int | None = Field(default=None, ge=1)
    no_udp: bool | None = None


@router.get("")
def get_identity(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return _identity_dump(config)


@router.post("/oidc/settings")
def save_oidc_settings(
    request: Request,
    payload: OidcAuthSettingsRequest,
) -> dict[str, object]:
    patch = {
        "enabled": payload.enabled,
        "connector": payload.connector,
        "pam": {
            "service": payload.pam_service,
            "gid_min": payload.pam_gid_min,
        },
        "radius": {
            "config_file": payload.radius_config_file,
            "groupconfig": payload.radius_groupconfig,
            "nas_identifier": payload.radius_nas_identifier,
            "group_separator": payload.radius_group_separator,
        },
    }
    previous = running_ocserv_conf(request)
    loaded_config, written = apply_config_patch(request, {"auth": {"oidc": patch}})
    # Enabling/disabling the PAM/RADIUS connector changes ocserv's `auth =`
    # lines, which only a restart applies.
    reload_result = ServerService(loaded_config).apply_config_change(previous)
    return {
        "status": "saved",
        "written": written,
        "identity": _identity_dump(loaded_config),
        "reload": ocserv_apply_result(reload_result),
    }


@router.post("/settings")
def save_identity_settings(
    request: Request,
    payload: IdentitySettingsRequest,
) -> dict[str, object]:
    patch = {
        "select_group_by_url": payload.select_group_by_url,
        "default_select_group": payload.default_select_group,
        "default_group_config": payload.default_group_config,
    }
    loaded_config, written = apply_config_patch(request, {"identity": patch})
    return {"status": "saved", "written": written, "identity": _identity_dump(loaded_config)}


@router.post("/oidc/providers")
def save_oidc_provider(
    request: Request,
    payload: OidcProviderRequest,
) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        providers = raw_collection(
            raw, Path(request.app.state.config_path), "identity", "oidc_providers"
        )
        existing = next((item for item in providers if item.get("name") == payload.name), {})
        data = payload.model_dump()
        # Omitted means preserve; explicit null/empty means remove the secret.
        if "client_secret" not in payload.model_fields_set and "client_secret" in existing:
            data["client_secret"] = existing["client_secret"]
        raw.setdefault("identity", {})["oidc_providers"] = replace_named(
            providers, payload.name, data
        )
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {"status": "saved", "written": written, "identity": _identity_dump(loaded_config)}


@router.delete("/oidc/providers/{name}")
def delete_oidc_provider(request: Request, name: str) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        providers = raw_collection(
            raw, Path(request.app.state.config_path), "identity", "oidc_providers"
        )
        raw.setdefault("identity", {})["oidc_providers"] = replace_named(providers, name, None)
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {"status": "deleted", "written": written, "identity": _identity_dump(loaded_config)}


@router.post("/groups")
def save_group_policy(
    request: Request,
    payload: GroupPolicyRequest,
) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        groups = raw_collection(
            raw, Path(request.app.state.config_path), "identity", "group_policies"
        )
        raw.setdefault("identity", {})["group_policies"] = replace_named(
            groups, payload.name, payload.model_dump()
        )
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {"status": "saved", "written": written, "identity": _identity_dump(loaded_config)}


@router.delete("/groups/{name}")
def delete_group_policy(request: Request, name: str) -> dict[str, object]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        groups = raw_collection(
            raw, Path(request.app.state.config_path), "identity", "group_policies"
        )
        raw.setdefault("identity", {})["group_policies"] = replace_named(groups, name, None)
        return raw

    loaded_config, written = apply_config_mutation(request, mutate)
    return {"status": "deleted", "written": written, "identity": _identity_dump(loaded_config)}


def _mask_provider(provider: OidcProviderConfig) -> dict[str, object]:
    """Mask secret fields via the centralized is_secret_key() check
    (matches client_secret) instead of a hand-picked exclude set, so a
    future secret-like field on this model is covered automatically."""
    data = provider.model_dump(mode="json")
    for key, value in data.items():
        if value not in (None, "", False) and is_secret_key(key):
            data[key] = "***"
    return data


def _identity_dump(config: AppConfig) -> dict[str, object]:
    return {
        "auth": config.auth.oidc.model_dump(mode="json"),
        "oidc_providers": [_mask_provider(provider) for provider in config.identity.oidc_providers],
        "group_policies": [
            group.model_dump(mode="json") for group in config.identity.group_policies
        ],
        "config_per_group_dir": str(config.identity.config_per_group_dir)
        if config.identity.config_per_group_dir
        else None,
        "select_group_by_url": config.identity.select_group_by_url,
        "default_select_group": config.identity.default_select_group,
        "default_group_config": str(config.identity.default_group_config)
        if config.identity.default_group_config
        else None,
    }

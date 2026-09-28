from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.api.routes_users import command_result
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.groups import GroupConfigService
from kornode.services.users import UserConfig

router = APIRouter(dependencies=[Depends(require_admin)])


class GroupConfigRequest(UserConfig):
    pass


@router.get("")
def list_groups(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [record.__dict__ for record in GroupConfigService(config).list_groups()]


@router.get("/{name}/config")
def get_group_config(request: Request, name: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        group_config = GroupConfigService(config).read_group_config(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return group_config.model_dump(mode="json")


@router.put("/{name}/config")
def save_group_config(
    request: Request,
    name: str,
    payload: GroupConfigRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = GroupConfigService(config).save_group_config(name, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(result, ("korctl", "identity", "group", "config", "save", name))


@router.delete("/{name}/config")
def delete_group_config(request: Request, name: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        deleted = GroupConfigService(config).delete_group_config(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(
        CommandResult(
            ("korctl", "identity", "group", "config", "delete", name),
            0,
            f"deleted: {str(deleted).lower()}\n",
            "",
            False,
        )
    )


@router.delete("/{name}")
def delete_group(request: Request, name: str) -> dict[str, object]:
    """Fully remove a group: its config-per-group file, its identity.group_policies
    entry (if any) and its membership on every user who still has it -- the three
    independent sources list_groups() reads from. Doing only one of these (e.g. just
    the config file, see delete_group_config above) would leave the group reappearing
    on the next load."""
    config: AppConfig = request.app.state.config
    service = GroupConfigService(config)
    try:
        service.validate_group_name(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    config_deleted = service.delete_group_config(name)

    cleared_members = []
    for user in service.user_config.list_users():
        remaining = [item for item in (user.groups or []) if item != name]
        if len(remaining) != len(user.groups or []):
            service.user_config.set_user_groups(user.username, remaining)
            cleared_members.append(user.username)

    policies = [item for item in config.identity.group_policies if item.name != name]
    policy_removed = len(policies) != len(config.identity.group_policies)
    apply_config_patch(
        request,
        {"identity": {"group_policies": [item.model_dump(mode="json") for item in policies]}},
    )

    summary_parts = []
    if config_deleted:
        summary_parts.append("config file removed")
    if policy_removed:
        summary_parts.append("group policy entry removed")
    if cleared_members:
        summary_parts.append(f"cleared from: {', '.join(cleared_members)}")
    summary = "; ".join(summary_parts) if summary_parts else "group had nothing to remove"

    return command_result(
        CommandResult(
            ("korctl", "identity", "group", "delete", name),
            0,
            f"{summary}\n",
            "",
            False,
        )
    )

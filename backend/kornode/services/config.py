from __future__ import annotations

import difflib
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.renderers import (
    DnsmasqConfigRenderer,
    OcservConfigRenderer,
    SupervisorConfigRenderer,
)
from kornode.services.files import FileManager
from kornode.services.rendered import RenderedFile
from kornode.services.secrets import collect_config_secrets, mask_text


class ConfigService:
    def __init__(self, file_manager: FileManager | None = None) -> None:
        self.file_manager = file_manager or FileManager()
        self.ocserv_renderer = OcservConfigRenderer()
        self.dnsmasq_renderer = DnsmasqConfigRenderer()
        self.supervisor_renderer = SupervisorConfigRenderer()

    def render_files(self, config: AppConfig) -> list[RenderedFile]:
        files = [
            RenderedFile(
                config.generated_path("ocserv-connect-script-kornode"),
                self.ocserv_renderer.render_connect_script(config),
                mode=0o755,
            ),
            RenderedFile(
                self.ocserv_renderer.target_path(config),
                self.ocserv_renderer.render(config),
            ),
            RenderedFile(
                self.supervisor_renderer.target_path(config),
                self.supervisor_renderer.render(config),
            ),
        ]
        if config.dns_tunnel_active():
            files.append(
                RenderedFile(
                    self.dnsmasq_renderer.target_path(config),
                    self.dnsmasq_renderer.render(config),
                )
            )
        if config.internal_dns.blocklist_enabled:
            from kornode.services.internal_dns import InternalDnsService

            internal_dns = InternalDnsService(config, self.file_manager)
            files.append(
                RenderedFile(
                    internal_dns.blocklist_conf_path(),
                    internal_dns.render_blocklist_conf(),
                )
            )
        for group in config.identity.group_policies:
            files.append(
                RenderedFile(
                    self.ocserv_renderer.group_policy_target_path(config, group),
                    self.ocserv_renderer.render_group_policy(group),
                )
            )
        if config.fabric.enabled:
            from kornode.services.fabric_groups import FabricGroupsService

            fabric_groups = FabricGroupsService(config, self.file_manager)
            files.extend(fabric_groups.render_files(fabric_groups.nodes()))
        return files

    def write_rendered_files(self, config: AppConfig) -> list[Path]:
        self.file_manager.ensure_dir(config.system.generated_dir)
        self.file_manager.ensure_dir(config.system.secrets_dir, mode=0o700)
        self.file_manager.ensure_dir(config.system.data_dir / "certs", mode=0o700)
        self.file_manager.ensure_dir(
            config.identity.config_per_group_dir
            or (config.system.generated_dir / "config-per-group")
        )
        if config.fabric.enabled:
            self.file_manager.ensure_dir(
                config.identity.config_per_user_dir
                or (config.system.generated_dir / "config-per-user")
            )
            from kornode.services.users import UserService

            UserService(config, files=self.file_manager).ensure_default_group()
        written: list[Path] = []
        rendered_files = self.render_files(config)
        for rendered in rendered_files:
            self.file_manager.atomic_write_text(rendered.path, rendered.content, rendered.mode)
            written.append(rendered.path)
        if config.fabric.enabled:
            from kornode.services.fabric_groups import FabricGroupsService

            for path in FabricGroupsService(config, self.file_manager).stale_files(rendered_files):
                path.unlink()
                written.append(path)
        return written

    def diff_rendered_files(self, config: AppConfig) -> str:
        secrets = collect_config_secrets(config)
        chunks: list[str] = []
        for rendered in self.render_files(config):
            current = rendered.path.read_text(encoding="utf-8") if rendered.path.exists() else ""
            diff = difflib.unified_diff(
                mask_text(current, secrets).splitlines(),
                mask_text(rendered.content, secrets).splitlines(),
                fromfile=str(rendered.path),
                tofile=f"{rendered.path} (rendered)",
                lineterm="",
            )
            chunks.extend(diff)
        return "\n".join(chunks)

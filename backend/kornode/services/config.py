from __future__ import annotations

import difflib
import logging
import sqlite3
from contextlib import nullcontext
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

LOGGER = logging.getLogger(__name__)


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
            files.extend(
                fabric_groups.render_files(fabric_groups.nodes(), fabric_groups.prefixes())
            )
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
            self._ensure_fabric_crl(config)
        written: list[Path] = []
        from kornode.services.fabric_groups import FabricGroupsService

        groups = FabricGroupsService(config, self.file_manager)
        with groups.locked() if config.fabric.enabled else nullcontext():
            rendered_files = self.render_files(config)
            for rendered in rendered_files:
                self.file_manager.atomic_write_text(rendered.path, rendered.content, rendered.mode)
                written.append(rendered.path)
            if config.fabric.enabled:
                for path in groups.stale_files(rendered_files):
                    path.unlink()
                    written.append(path)
        self._recompile_bundles(config)
        return written

    def _recompile_bundles(self, config: AppConfig) -> None:
        """Hub host/port/pin and fabric settings live in the bundles: every
        saved configuration recompiles them. The control API repeats this at
        start, so a failure here is logged, not fatal to the save."""
        if not config.control.enabled:
            return
        from kornode.bundle.errors import BundleError
        from kornode.registry.db import RegistryError, migrate, open_registry, transaction
        from kornode.registry.repository import Registry
        from kornode.services.bundle import BundleService

        try:
            conn = open_registry(config.system.data_dir / "registry.db")
            try:
                migrate(conn)
                with transaction(conn):
                    BundleService(config).compile_all(Registry(conn), "hub configuration saved")
            finally:
                conn.close()
        except (BundleError, RegistryError, OSError, sqlite3.Error) as exc:
            LOGGER.warning("bundle recompilation after config save failed: %s", exc)

    def _ensure_fabric_crl(self, config: AppConfig) -> None:
        # ocserv refuses to start with `crl =` pointing at a missing file.
        if not config.cert_path("ca.key").exists():
            return
        from kornode.services.certificates import CertificateService

        CertificateService(config, files=self.file_manager).ensure_crl()

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

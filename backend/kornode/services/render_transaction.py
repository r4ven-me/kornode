"""Render the authoritative configuration under the shared source lock."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from kornode.config.env import config_environment
from kornode.config.loader import load_yaml_file, validate_config_data
from kornode.config.models import AppConfig
from kornode.services.config import ConfigService
from kornode.services.config_store import ConfigVersionConflict, config_lock


def render_config(path: Path, *, env_file: Path | None = None) -> list[str]:
    """Serialize reload and all rendered writes with configuration mutations.

    The canonical target selects source/lock identity, not the environment:
    symlink callers retain their own .env and secret-reference context.
    No YAML is persisted and no cached application state is installed.
    """
    with rendered_configuration(path, env_file=env_file) as (_, written):
        return written


@contextmanager
def rendered_configuration(
    path: Path, *, env_file: Path | None = None, service: ConfigService | None = None
) -> Iterator[tuple[AppConfig, list[str]]]:
    """Keep render-dependent runtime actions inside the same source transaction.

    Call only from unlocked entry points. Already-locked mutation callbacks must
    use their validated candidate directly, not reacquire this non-reentrant lock.
    """
    with config_lock(path) as target, config_environment(path, env_file):
        config = validate_config_data(load_yaml_file(target), path, env_file=env_file)
        if path.resolve() != target:
            raise ConfigVersionConflict("configuration source alias changed; retry")
        written = [str(item) for item in (service or ConfigService()).write_rendered_files(config)]
        yield config, written

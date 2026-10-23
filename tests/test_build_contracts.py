"""Offline packaging/release contracts; no Docker builds, Git writes or publishing."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA256 = "42ced08958b9576ab134fcb7bdc7f8df5e13214fd147855f99021fedcf0eedbe"
COMMIT = "a" * 40


def stage(name: str) -> str:
    dockerfile = (ROOT / "Dockerfile").read_text()
    return re.search(rf"^FROM [^\n]+ AS {name}\n(.*?)(?=^FROM |\Z)", dockerfile, re.M | re.S)[1]


def recipe(target: str) -> str:
    text = (ROOT / "Makefile").read_text()
    body = re.search(rf"^{target}:[^\n]*\n((?:\t[^\n]*\n)+)", text, re.M)[1]
    return "\n".join(line.removeprefix("\t").removeprefix("@") for line in body.splitlines())


def workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())


def test_backend_test_stage_has_repository_contract_inputs() -> None:
    sources = []
    assert "FROM backend-test-deps AS backend-test" in (ROOT / "Dockerfile").read_text()
    for line in stage("backend-test-deps").splitlines():
        if line.startswith("COPY "):
            sources.extend(shlex.split(line)[1:-1])
    required = (
        "pyproject.toml",
        "README.md",
        "parity.yaml",
        ".env.example",
        "config.example.yaml",
        "Dockerfile",
        "Dockerfile.agent",
        "Makefile",
        ".dockerignore",
        "compose.yaml",
        "compose.agent.yaml",
        "compose.web.yaml",
        "backend",
        "templates",
        "tests",
        "examples",
        "frontend/src",
        "docs",
        ".github",
        "agent",
    )
    for name in required:
        path = ROOT / name
        assert path.exists(), name
        assert any(path in ROOT.glob(pattern) for pattern in sources), f"Missing COPY: {name}"
    assert "python -m pytest -m 'not netlab'" in stage("backend-test")
    assert "python -m mypy --explicit-package-bases tests/e2e" in stage("backend-test")
    assert "gnutls-bin" in stage("backend-test-deps")
    assert "pip install --no-cache-dir '.[dev]'" in stage("backend-test-deps")
    assert "COPY . ." not in stage("backend-test-deps")


def test_context_excludes_worktrees_metadata_and_secrets_but_keeps_fixtures() -> None:
    patterns = (ROOT / ".dockerignore").read_text().splitlines()
    assert {".git", "**/.git", ".ai", ".claude", ".serena", "**/.env", "**/.env.*"} <= set(patterns)
    assert patterns.index("!.env.example") > patterns.index("**/.env.*")
    assert not {"docs", ".github", "frontend/src", "tests", "parity.yaml"} & set(patterns)


def test_ocserv_pin_has_upstream_provenance_and_unconditional_verification() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert f"ARG OCSERV_SHA256={SHA256}" in text
    assert "https://www.infradead.org/ocserv/download/ocserv-1.5.0.tar.xz.sha256sum" in text
    assert "HTTPS trust, not an independently verified GPG signature" in text
    build = stage("ocserv-builder")
    assert "--proto '=https' --proto-redir '=https'" in build
    assert build.index("sha256sum -c -") < build.index("&& tar ") < build.index("meson setup")
    assert 'if [ -n "${OCSERV_SHA256}" ]' not in build
    assert "WARNING:" not in build


@pytest.mark.parametrize(
    ("version", "digest", "success"),
    [
        ("1.5.0", SHA256, True),
        ("1.5.0", "", False),
        ("1.5.0", "invalid", False),
        ("1.6.0", SHA256, False),
        ("1.6.0", "", False),
        ("1.6.0", "1" * 64, True),
    ],
)
def test_ocserv_pin_guard(version: str, digest: str, success: bool) -> None:
    guard = re.search(r"^RUN (\[\[.*?)(?=\n\n)", stage("ocserv-builder"), re.M | re.S)[1]
    result = subprocess.run(
        ["bash", "-Eeuo", "pipefail", "-c", guard],
        env={**os.environ, "OCSERV_VERSION": version, "OCSERV_SHA256": digest},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is success


@pytest.fixture
def fake_tools(tmp_path: Path) -> Path:
    """Only read-only fake commands are accepted, even if a recipe regresses."""
    program = tmp_path / "fake-tool"
    program.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:1] == ['api']:\n"
        "    print(os.environ.get('FAKE_CI', 'true'))\n"
        "    sys.exit(int(os.environ.get('FAKE_CI_CODE', '0')))\n"
        "if 'rev-parse' in args:\n"
        "    print(os.environ.get('FAKE_HEAD', 'a' * 40))\n"
        "    sys.exit(int(os.environ.get('FAKE_HEAD_CODE', '0')))\n"
        "if 'status' in args:\n"
        "    print(os.environ.get('FAKE_STATUS', ''), end='')\n"
        "    sys.exit(int(os.environ.get('FAKE_STATUS_CODE', '0')))\n"
        "if 'show-ref' in args:\n"
        "    sys.exit(int(os.environ.get('FAKE_LOCAL_TAG_CODE', '1')))\n"
        "if 'ls-remote' in args:\n"
        "    print(os.environ.get('FAKE_REMOTE_TAG', ''), end='')\n"
        "    sys.exit(int(os.environ.get('FAKE_REMOTE_CODE', '0')))\n"
        "if args[:3] == ['buildx', 'imagetools', 'inspect']:\n"
        "    print(os.environ.get('FAKE_MANIFEST', 'ERROR: example:v1.1.5: not found'))\n"
        "    sys.exit(int(os.environ.get('FAKE_MANIFEST_CODE', '1')))\n"
        "raise SystemExit('Forbidden command in offline release test')\n"
    )
    program.chmod(0o755)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.1.5"\n')
    return program


def run_guard(
    name: str, tool: Path, overrides: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    script = recipe(name).replace("$$", "$")
    for key, value in {
        "GIT": shlex.quote(str(tool)),
        "DOCKER": shlex.quote(str(tool)),
        "PYTHON": shlex.quote(sys.executable),
        "REMOTE_IMAGE": "example/hub",
        "GHCR_IMAGE": "ghcr.io/example/hub",
    }.items():
        script = script.replace(f"$({key})", value)
    assert "$(MAKE)" not in script
    return subprocess.run(
        ["sh", "-c", script],
        cwd=tool.parent,
        env={
            **os.environ,
            "RELEASE_COMMIT": COMMIT,
            "VERSION": "1.1.5",
            "TAG": "v1.1.5",
            "EXTRA_TAG": "",
            **(overrides or {}),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_reviewed_clean_commit_is_accepted(fake_tools: Path) -> None:
    result = run_guard("release-preflight", fake_tools, {"EXTRA_TAG": "raven"})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "overrides",
    [
        {"RELEASE_COMMIT": ""},
        {"RELEASE_COMMIT": "a" * 7},
        {"FAKE_HEAD": "b" * 40},
        {"FAKE_HEAD_CODE": "128"},
        {"FAKE_STATUS": " M README.md"},
        {"FAKE_STATUS": "M  README.md"},
        {"FAKE_STATUS": "?? private.txt"},
        {"FAKE_STATUS_CODE": "128"},
        {"TAG": "latest"},
        {"TAG": "latest", "PYTHONOPTIMIZE": "1"},
        {"VERSION": "9.9.9"},
        {"EXTRA_TAG": "v1.0.0"},
        {"EXTRA_TAG": "1.0.0"},
        {"EXTRA_TAG": "latest"},
        {"EXTRA_TAG": "bad;alias"},
    ],
)
def test_release_preflight_fails_closed(fake_tools: Path, overrides: dict[str, str]) -> None:
    assert run_guard("release-preflight", fake_tools, overrides).returncode != 0


@pytest.mark.parametrize(
    ("overrides", "success"),
    [
        ({}, True),
        ({"FAKE_LOCAL_TAG_CODE": "0"}, False),
        ({"FAKE_LOCAL_TAG_CODE": "128"}, False),
        ({"FAKE_REMOTE_TAG": COMMIT}, False),
        ({"FAKE_REMOTE_CODE": "128"}, False),
    ],
)
def test_git_version_tags_are_create_only(
    fake_tools: Path, overrides: dict[str, str], success: bool
) -> None:
    assert (run_guard("release-git-check", fake_tools, overrides).returncode == 0) is success


@pytest.mark.parametrize(
    ("message", "code", "success"),
    [
        ("ERROR: example:v1.1.5: not found", "1", True),
        ("manifest unknown", "1", True),
        ("MANIFEST_UNKNOWN: missing", "1", True),
        ("sha256:existing", "0", False),
        ("unauthorized", "1", False),
        ("TLS handshake timeout", "1", False),
        ("connection refused", "1", False),
        ("docker: command not found", "127", False),
        ("manifest unknown", "127", False),
        ("manifest unknown\nunauthorized", "1", False),
    ],
)
def test_registry_absence_must_be_known(
    fake_tools: Path, message: str, code: str, success: bool
) -> None:
    result = run_guard(
        "release-images-check", fake_tools, {"FAKE_MANIFEST": message, "FAKE_MANIFEST_CODE": code}
    )
    assert (result.returncode == 0) is success


def test_publication_is_gated_and_does_not_stage_or_commit() -> None:
    text = (ROOT / "Makefile").read_text()
    assert not re.search(r"\$\(GIT\) (?:add|commit|tag -d|push .*--force(?: |$))", text)
    assert "refs/tags/$(TAG):refs/tags/$(TAG)" in text
    assert "--force-with-lease=refs/tags/$$EXTRA_TAG:$$old" in text
    assert '$(GIT) -c core.hooksPath=/dev/null tag -f "$$EXTRA_TAG"' in text
    assert ".NOTPARALLEL: release docker-release docker-push git-tag release-check" in text
    assert "git-tag: release-check release-git-check" in text
    assert "docker-push: release-check release-images-check docker-build docker-cli-check" in text
    checks = recipe("release-check")
    for required in (
        "check render",
        "frontend-install",
        "frontend-test",
        "frontend-build",
        "frontend-audit",
        "docker-test",
        "release-preflight",
    ):
        assert f"$(MAKE) {required}" in checks
    assert recipe("docker-push").startswith("$(MAKE) release-preflight release-images-check")
    assert recipe("git-tag").startswith("$(MAKE) release-preflight release-git-check")


def test_ci_builds_only_bounded_test_stages() -> None:
    job = workflow("ci")["jobs"]["container-tests"]
    assert 1 <= job["timeout-minutes"] <= 30
    builds = [s["with"] for s in job["steps"] if s.get("uses", "").startswith("docker/build-push")]
    assert {build["target"] for build in builds} == {"frontend-test", "backend-test"}
    assert all(build["push"] is False for build in builds)


def test_release_requires_exact_main_ci_and_emits_attestations() -> None:
    spec = workflow("release-image")
    job = spec["jobs"]["publish"]
    assert "github.ref_protected" in job["if"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert "head_repository.full_name == github.repository" in job["if"]
    assert 1 <= job["timeout-minutes"] <= 60
    assert spec["concurrency"]["cancel-in-progress"] is False
    steps = job["steps"]
    gate = next(s for s in steps if "Require successful full CI" in s.get("name", ""))
    assert (
        '-f head_sha="$RELEASE_COMMIT" -f branch=main -f event=push -f status=success'
        in gate["run"]
    )
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False
    build = next(s for s in steps if s.get("uses", "").startswith("docker/build-push"))
    assert build["if"] == "steps.exists.outputs.published != 'true'"
    assert checkout["with"]["ref"] == "${{ env.RELEASE_COMMIT }}"
    assert build["with"]["sbom"] is True
    assert build["with"]["provenance"] == "mode=min"
    assert "build-args" not in build["with"]  # no empty variable overriding the reviewed pin
    assert steps.index(gate) < steps.index(build)
    for step in steps:
        script = step.get("run", "")
        if "<<'PY'\n" in script:
            compile(script.split("<<'PY'\n")[1].rsplit("\nPY", 1)[0], "<workflow>", "exec")


@pytest.mark.parametrize(
    ("message", "code", "published"),
    [
        ("manifest unknown", "1", "false"),
        ("digest exists", "0", "true"),
        ("unauthorized", "1", None),
        ("TLS handshake timeout", "1", None),
    ],
)
def test_release_workflow_registry_guard(
    fake_tools: Path, message: str, code: str, published: str | None
) -> None:
    fake_tools.with_name("docker").symlink_to(fake_tools)
    output = fake_tools.parent / "output"
    step = next(
        s for s in workflow("release-image")["jobs"]["publish"]["steps"] if s.get("id") == "exists"
    )
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=fake_tools.parent,
        env={
            **os.environ,
            "PATH": f"{fake_tools.parent}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(output),
            "IMAGE": "example/hub",
            "VERSION": "1.1.5",
            "FAKE_MANIFEST": message,
            "FAKE_MANIFEST_CODE": code,
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (published is not None)
    assert output.read_text() == f"published={published}\n" if published else not output.exists()


def test_agent_shared_crypto_floor_matches_hub() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requirement = next(
        d for d in project["project"]["dependencies"] if d.startswith("cryptography")
    )
    assert f"'{requirement}'" in (ROOT / "Dockerfile.agent").read_text()


@pytest.mark.parametrize("tampered", [False, True])
def test_checksum_mismatch_stops_before_extraction(tmp_path: Path, tampered: bool) -> None:
    import hashlib

    archive = tmp_path / "source.tar.xz"
    archive.write_bytes(b"offline-test-source")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if tampered:
        archive.write_bytes(b"tampered-source")
    marker = tmp_path / "would-extract"
    check = re.search(r'&& (echo "\$\{OCSERV_SHA256\}.*?sha256sum -c -)', stage("ocserv-builder"))[
        1
    ]
    check = check.replace("/tmp/", f"{tmp_path}/").replace(
        "ocserv-${OCSERV_VERSION}.tar.xz", archive.name
    )
    result = subprocess.run(
        ["bash", "-Eeuo", "pipefail", "-c", f"{check} && touch {shlex.quote(str(marker))}"],
        env={**os.environ, "OCSERV_SHA256": digest},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (not tampered)
    assert marker.exists() is (not tampered)


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"FAKE_CI": "false"},
        {"FAKE_CI_CODE": "1"},
        {"FAKE_HEAD": "b" * 40},
        {"FAKE_HEAD_CODE": "128"},
        {"FAKE_STATUS": "?? private.txt"},
        {"FAKE_STATUS_CODE": "128"},
    ],
)
def test_workflow_ci_gate_fails_closed(fake_tools: Path, overrides: dict[str, str]) -> None:
    for command in ("gh", "git"):
        fake_tools.with_name(command).symlink_to(fake_tools)
    gate = next(
        step
        for step in workflow("release-image")["jobs"]["publish"]["steps"]
        if "Require successful full CI" in step.get("name", "")
    )
    result = subprocess.run(
        ["bash", "-c", gate["run"]],
        cwd=fake_tools.parent,
        env={
            **os.environ,
            "PATH": f"{fake_tools.parent}:{os.environ['PATH']}",
            "RELEASE_COMMIT": COMMIT,
            "GITHUB_REPOSITORY": "example/hub",
            **overrides,
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (not overrides)


def test_workflow_shell_blocks_parse_without_running_them() -> None:
    for name in ("ci", "release-image", "e2e"):
        for job in workflow(name)["jobs"].values():
            for step in job["steps"]:
                if "run" not in step:
                    continue
                result = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                assert result.returncode == 0, result.stderr

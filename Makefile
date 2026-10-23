.PHONY: help install test netlab e2e e2e-plan parity lint typecheck check render docker-build git-tag docker-tag docker-push docker-release docker-test docker-cli-check frontend-install frontend-build frontend-test frontend-e2e frontend-audit release release-preflight release-check release-git-check release-images-check

PYTHON ?= $(shell if [ -x .venv/bin/python ]; then printf '%s' '.venv/bin/python'; else printf '%s' 'python'; fi)
NPM ?= npm
DOCKER ?= docker
GIT ?= git
VERSION ?= $(shell $(PYTHON) -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
TAG ?= v$(VERSION)
IMAGE ?= kornode
REMOTE_IMAGE ?= r4venme/kornode
GHCR_IMAGE ?= ghcr.io/r4ven-me/kornode
# Migration: commit/review/push separately, then run:
# make release RELEASE_COMMIT=<full reviewed HEAD SHA> [EXTRA_TAG=raven]
# No automatic staging/commit/branch push. Version tags are never replaced.
# EXTRA_TAG is an explicitly mutable deployment alias (git + both registries).
# Registry-side immutable version-tag policies are still recommended: registries
# offer no portable create-only push, nor an atomic multi-registry transaction.
RELEASE_COMMIT ?=
EXTRA_TAG ?=
export RELEASE_COMMIT VERSION TAG EXTRA_TAG

# Prerequisites must stay ordered even under make -j: all safe checks complete
# before any tag/push, and a failed check must stop publication.
.NOTPARALLEL: release docker-release docker-push git-tag release-check

help:
	@printf '%s\n' 'Targets: install test lint typecheck check e2e-plan e2e render docker-build git-tag docker-tag docker-push docker-release docker-test docker-cli-check frontend-install frontend-build frontend-test frontend-e2e frontend-audit release'
	@printf '%s\n' 'Korvus Client lives in its own repository: https://github.com/r4ven-me/korclient'
	@printf '%s\n' 'Release migration: commit/review/push separately; make release RELEASE_COMMIT=<full reviewed HEAD SHA> [EXTRA_TAG=raven]'
	@printf '%s\n' 'Version tags are immutable; EXTRA_TAG is a mutable deployment alias. Registry errors abort publication.'

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest

parity:
	$(PYTHON) -m pytest tests/test_parity.py -q

netlab:
	$(PYTHON) -m pytest -m netlab -v

# plan is offline. e2e additionally requires env opt-in, pinned SSH and VM markers.
e2e-plan:
	$(PYTHON) -m tests.e2e plan

e2e:
	$(PYTHON) -m pytest tests/e2e --e2e-run -q --tb=short

lint:
	$(PYTHON) -m ruff check backend tests

typecheck:
	$(PYTHON) -m mypy backend
	$(PYTHON) -m mypy --explicit-package-bases tests/e2e

check: lint typecheck test

render:
	$(PYTHON) -m kornode --config config.example.yaml config render --dry-run

docker-build:
	$(DOCKER) build -t $(IMAGE):latest .

# Read-only and fail closed, including untracked files and Git failures. A full
# explicit SHA is an operator acknowledgement, not a substitute for code review.
release-preflight:
	@set -eu; \
	printf '%s\n' "$$RELEASE_COMMIT" | grep -Eq '^([0-9a-f]{40}|[0-9a-f]{64})$$' \
	  || { echo 'Set RELEASE_COMMIT to the full reviewed HEAD SHA' >&2; exit 1; }; \
	head="$$($(GIT) --no-pager rev-parse --verify HEAD)"; \
	test "$$RELEASE_COMMIT" = "$$head" \
	  || { echo 'Reviewed commit is not HEAD' >&2; exit 1; }; \
	state="$$($(GIT) --no-optional-locks status --porcelain --untracked-files=all)"; \
	test -z "$$state" || { echo 'Release requires a clean tree (including untracked files)' >&2; exit 1; }; \
	$(PYTHON) -c 'import os, re, sys, tomllib; v=tomllib.load(open("pyproject.toml", "rb"))["project"]["version"]; re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*)", v) or sys.exit("Invalid version"); (os.environ["VERSION"] == v and os.environ["TAG"] == "v"+v) or sys.exit("VERSION/TAG must match pyproject.toml"); alias=os.environ["EXTRA_TAG"]; (not alias or (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", alias) and not re.match(r"v?[0-9]", alias) and alias not in {"latest", "v"+v})) or sys.exit("EXTRA_TAG must be a non-version deployment alias")'

release-check: release-preflight
	$(MAKE) check render
	$(MAKE) frontend-install
	$(MAKE) frontend-test
	$(MAKE) frontend-build
	$(MAKE) frontend-audit
	$(MAKE) docker-test
	$(MAKE) release-preflight

release-git-check: release-preflight
	@set -eu; \
	if $(GIT) --no-pager show-ref --verify --quiet "refs/tags/$$TAG"; then \
	  echo 'Version tag already exists locally; refusing to replace it' >&2; exit 1; \
	else test "$$?" -eq 1; fi; \
	remote="$$($(GIT) --no-pager ls-remote --tags origin "refs/tags/$$TAG")"; \
	test -z "$$remote" || { echo 'Version tag already exists on origin' >&2; exit 1; }

release-images-check: release-preflight
	@set -eu; \
	for image in $(REMOTE_IMAGE) $(GHCR_IMAGE); do \
	  if output="$$($(DOCKER) buildx imagetools inspect "$$image:$$TAG" 2>&1)"; then \
	    echo 'Version image already exists; refusing to replace it' >&2; exit 1; \
	  else \
	    status="$$?"; \
	    test "$$status" -eq 1 \
	      && test "$$(printf '%s\n' "$$output" | wc -l)" -eq 1 \
	      && printf '%s\n' "$$output" | grep -Eq '^(ERROR: .*: )?(manifest unknown|MANIFEST_UNKNOWN)(: .*)?$$|^ERROR: [^ ]+: not found$$' \
	      || { echo 'Cannot establish version image absence; check registry access' >&2; exit 1; }; \
	  fi; \
	done

git-tag: release-check release-git-check
	$(MAKE) release-preflight release-git-check
	$(GIT) -c core.hooksPath=/dev/null tag "$(TAG)" "$(RELEASE_COMMIT)"
	$(GIT) -c core.hooksPath=/dev/null push origin "refs/tags/$(TAG):refs/tags/$(TAG)"
ifneq ($(strip $(EXTRA_TAG)),)
	@set -eu; \
	remote="$$($(GIT) --no-pager ls-remote --tags origin "refs/tags/$$EXTRA_TAG")"; \
	old="$$(printf '%s' "$$remote" | cut -f1)"; \
	$(GIT) -c core.hooksPath=/dev/null tag -f "$$EXTRA_TAG" "$$RELEASE_COMMIT"; \
	$(GIT) -c core.hooksPath=/dev/null push \
	  "--force-with-lease=refs/tags/$$EXTRA_TAG:$$old" origin \
	  "refs/tags/$$EXTRA_TAG:refs/tags/$$EXTRA_TAG"
endif

docker-tag:
	$(DOCKER) tag $(IMAGE):latest $(REMOTE_IMAGE):latest
	$(DOCKER) tag $(IMAGE):latest $(REMOTE_IMAGE):$(TAG)
	$(DOCKER) tag $(IMAGE):latest $(GHCR_IMAGE):latest
	$(DOCKER) tag $(IMAGE):latest $(GHCR_IMAGE):$(TAG)
ifneq ($(strip $(EXTRA_TAG)),)
	$(DOCKER) tag $(IMAGE):latest $(REMOTE_IMAGE):$(EXTRA_TAG)
	$(DOCKER) tag $(IMAGE):latest $(GHCR_IMAGE):$(EXTRA_TAG)
endif

# Direct publication entry points cannot bypass the checks or publish a stale
# local :latest image. Recheck the tree and registry immediately before pushing.
docker-push: release-check release-images-check docker-build docker-cli-check docker-tag
	$(MAKE) release-preflight release-images-check
	$(DOCKER) push $(REMOTE_IMAGE):$(TAG)
	$(DOCKER) push $(GHCR_IMAGE):$(TAG)
	$(DOCKER) push $(REMOTE_IMAGE):latest
	$(DOCKER) push $(GHCR_IMAGE):latest
ifneq ($(strip $(EXTRA_TAG)),)
	$(DOCKER) push $(REMOTE_IMAGE):$(EXTRA_TAG)
	$(DOCKER) push $(GHCR_IMAGE):$(EXTRA_TAG)
endif

# Both historical entry points retain both registries and latest/EXTRA_TAG.
# Only release creates Git tags; docker-release remains image-only.
docker-release: docker-push

release: release-check release-git-check release-images-check docker-push git-tag

docker-test:
	$(DOCKER) build --target frontend-test -t kornode:frontend-test .
	$(DOCKER) build --target backend-test -t kornode:test .

docker-cli-check:
	$(DOCKER) run --rm --entrypoint korctl $(IMAGE):latest config render --dry-run

frontend-install:
	$(NPM) --prefix frontend ci

frontend-build: frontend-install
	$(NPM) --prefix frontend run build

frontend-test:
	$(NPM) --prefix frontend test

frontend-e2e:
	$(NPM) --prefix frontend run test:e2e

frontend-audit:
	$(NPM) --prefix frontend audit --audit-level=moderate

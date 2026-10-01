.PHONY: help install test lint typecheck check render docker-build git-tag docker-tag docker-push docker-release docker-test docker-cli-check frontend-install frontend-build frontend-test frontend-e2e frontend-audit release

PYTHON ?= $(shell if [ -x .venv/bin/python ]; then printf '%s' '.venv/bin/python'; else printf '%s' 'python'; fi)
NPM ?= npm
DOCKER ?= docker
GIT ?= git
VERSION ?= $(shell $(PYTHON) -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
TAG ?= v$(VERSION)
IMAGE ?= kornode
REMOTE_IMAGE ?= r4venme/kornode
GHCR_IMAGE ?= ghcr.io/r4ven-me/kornode
MSG ?= Release $(TAG)
# Optional second tag moved to the same commit/image alongside the version
# tag, e.g. a floating deployment tag: make release EXTRA_TAG=raven
EXTRA_TAG ?=

help:
	@printf '%s\n' 'Targets: install test lint typecheck check render docker-build git-tag docker-tag docker-push docker-release docker-test docker-cli-check frontend-install frontend-build frontend-test frontend-e2e frontend-audit release'
	@printf '%s\n' 'Korvus Client lives in its own repository: https://github.com/r4ven-me/korclient'
	@printf '%s\n' 'EXTRA_TAG=<name> on release/docker-tag/docker-push/git-tag also moves that tag (git + both registries) to this release, e.g. make release EXTRA_TAG=raven'

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check backend tests

typecheck:
	$(PYTHON) -m mypy backend

check: lint typecheck test

render:
	$(PYTHON) -m kornode --config config.example.yaml config render --dry-run

docker-build:
	$(DOCKER) build -t $(IMAGE):latest .

# $(1): tag name to (re)create locally and force-push to origin.
define retag_and_push
	@if $(GIT) rev-parse -q --verify "refs/tags/$(1)" >/dev/null; then \
		echo "Tag $(1) already exists locally, recreating it"; \
		$(GIT) tag -d "$(1)"; \
	fi
	@if $(GIT) ls-remote --exit-code --tags origin "refs/tags/$(1)" >/dev/null 2>&1; then \
		echo "Tag $(1) already exists on origin, deleting it there too"; \
		$(GIT) push origin ":refs/tags/$(1)"; \
	fi
	$(GIT) tag "$(1)"
	$(GIT) push origin "$(1)"
endef

git-tag:
	$(call retag_and_push,$(TAG))
ifneq ($(strip $(EXTRA_TAG)),)
	$(call retag_and_push,$(EXTRA_TAG))
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

docker-push:
	$(DOCKER) push $(REMOTE_IMAGE):latest
	$(DOCKER) push $(REMOTE_IMAGE):$(TAG)
	$(DOCKER) push $(GHCR_IMAGE):latest
	$(DOCKER) push $(GHCR_IMAGE):$(TAG)
ifneq ($(strip $(EXTRA_TAG)),)
	$(DOCKER) push $(REMOTE_IMAGE):$(EXTRA_TAG)
	$(DOCKER) push $(GHCR_IMAGE):$(EXTRA_TAG)
endif

docker-release: docker-build docker-tag docker-push

release: test
	$(GIT) add -A
	$(GIT) diff --cached --quiet || $(GIT) commit -m "$(MSG)"
	$(GIT) push
	$(MAKE) git-tag
	$(MAKE) docker-release

docker-test:
	$(DOCKER) build --target frontend-test -t kornode:frontend-test .
	$(DOCKER) build --target backend-test -t kornode:test .

docker-cli-check:
	$(DOCKER) run --rm --entrypoint korctl kornode:latest config render --dry-run

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

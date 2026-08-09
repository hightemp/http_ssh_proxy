SHELL := /bin/bash

BINARY_NAME := http_ssh_proxy
GO ?= go
GOBUILD := $(GO) build
VERSION_FILE ?= VERSION
REMOTE ?= origin
BRANCH ?= main

.PHONY: build build-static test release

build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/http_ssh_proxy

build-static:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-w' -o $(BINARY_NAME)_static ./cmd/http_ssh_proxy

test:
	$(GO) test -race ./...

release: test
	@set -euo pipefail; \
	if [[ ! -f "$(VERSION_FILE)" ]]; then \
		echo "Error: $(VERSION_FILE) not found" >&2; \
		exit 1; \
	fi; \
	version="$$(tr -d '[:space:]' < "$(VERSION_FILE)")"; \
	if [[ "$$version" == v* ]]; then tag="$$version"; else tag="v$$version"; fi; \
	if ! grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' <<< "$$tag"; then \
		echo "Error: invalid semantic version in $(VERSION_FILE): $$version" >&2; \
		exit 1; \
	fi; \
	current_branch="$$(git branch --show-current)"; \
	if [[ "$$current_branch" != "$(BRANCH)" ]]; then \
		echo "Error: release must run on branch $(BRANCH), current branch is $$current_branch" >&2; \
		exit 1; \
	fi; \
	if ! git remote get-url "$(REMOTE)" >/dev/null 2>&1; then \
		echo "Error: git remote $(REMOTE) does not exist" >&2; \
		exit 1; \
	fi; \
	other_changes="$$(git status --porcelain --untracked-files=all | sed '\| $(VERSION_FILE)$$|d')"; \
	if [[ -n "$$other_changes" ]]; then \
		echo "Error: commit or stash changes outside $(VERSION_FILE) before releasing:" >&2; \
		echo "$$other_changes" >&2; \
		exit 1; \
	fi; \
	git add -- "$(VERSION_FILE)"; \
	if git diff --cached --quiet -- "$(VERSION_FILE)"; then \
		echo "Error: $(VERSION_FILE) has not changed" >&2; \
		exit 1; \
	fi; \
	git commit --only -m "chore(release): $$tag" -- "$(VERSION_FILE)"; \
	git tag --force --annotate "$$tag" --message "Release $$tag"; \
	git push --force --atomic "$(REMOTE)" \
		"HEAD:refs/heads/$(BRANCH)" \
		"refs/tags/$$tag:refs/tags/$$tag"; \
	echo "Released $$tag"

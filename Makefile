SHELL := /bin/bash

BINARY_NAME := http_ssh_proxy
GO ?= go
GOBUILD := $(GO) build
VERSION_FILE ?= VERSION
REMOTE ?= origin
BRANCH ?= main
COVERAGE_FILE ?= coverage.out
COVERAGE_MIN ?= 90
GOVULNCHECK ?= govulncheck

.PHONY: build build-static test vet coverage fuzz module-check vulncheck check release

build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/http_ssh_proxy

build-static:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-w' -o $(BINARY_NAME)_static ./cmd/http_ssh_proxy

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

coverage:
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=$(COVERAGE_FILE) ./...
	@coverage="$$( $(GO) tool cover -func=$(COVERAGE_FILE) | awk '/^total:/ { gsub("%", "", $$3); print $$3 }' )"; \
	awk -v actual="$$coverage" -v minimum="$(COVERAGE_MIN)" 'BEGIN { \
		if (actual + 0 < minimum + 0) { \
			printf "Coverage %.1f%% is below required %.1f%%\n", actual, minimum > "/dev/stderr"; \
			exit 1; \
		} \
		printf "Coverage %.1f%% meets required %.1f%%\n", actual, minimum; \
	}'

fuzz:
	$(GO) test ./internal/proxy -run='^$$' -fuzz=FuzzParseBasicProxyAuthorization -fuzztime=5s
	$(GO) test ./internal/proxy -run='^$$' -fuzz=FuzzRemoveHopByHopHeaders -fuzztime=5s

module-check:
	$(GO) mod verify
	$(GO) mod tidy -diff
	$(GO) list -mod=readonly -deps ./... >/dev/null

vulncheck:
	$(GOVULNCHECK) ./...

check: module-check vet coverage vulncheck

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

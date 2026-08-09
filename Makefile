SHELL := /bin/bash

BINARY_NAME := http_ssh_proxy
MODULE_PATH := github.com/hightemp/http_ssh_proxy
GO ?= go
GOBUILD := $(GO) build
VERSION_FILE ?= VERSION
VERSION ?= $(shell version="$$(tr -d '[:space:]' < "$(VERSION_FILE)" 2>/dev/null)"; if [[ -z "$$version" ]]; then printf dev; elif [[ "$$version" == v* ]]; then printf '%s' "$$version"; else printf 'v%s' "$$version"; fi)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_LDFLAGS := -X $(MODULE_PATH)/internal/buildinfo.Version=$(VERSION) -X $(MODULE_PATH)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE_PATH)/internal/buildinfo.BuildTime=$(BUILD_TIME)
REMOTE ?= origin
BRANCH ?= main
COVERAGE_FILE ?= coverage.out
COVERAGE_MIN ?= 90
GOVULNCHECK ?= govulncheck

.PHONY: build build-static test vet coverage fuzz module-check vulncheck check release rewrite-release-tag

build:
	$(GOBUILD) -trimpath -ldflags "$(BUILD_LDFLAGS)" -o $(BINARY_NAME) -v ./cmd/http_ssh_proxy

build-static:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -trimpath -ldflags "-s -w $(BUILD_LDFLAGS)" -o $(BINARY_NAME)_static ./cmd/http_ssh_proxy

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
	git fetch --no-tags "$(REMOTE)" "refs/heads/$(BRANCH):refs/remotes/$(REMOTE)/$(BRANCH)"; \
	if ! git merge-base --is-ancestor "refs/remotes/$(REMOTE)/$(BRANCH)" HEAD; then \
		echo "Error: local $(BRANCH) is not based on $(REMOTE)/$(BRANCH); update it before releasing" >&2; \
		exit 1; \
	fi; \
	if git show-ref --verify --quiet "refs/tags/$$tag"; then \
		echo "Error: local tag $$tag already exists; release tags are immutable by default" >&2; \
		exit 1; \
	fi; \
	if git ls-remote --exit-code --tags "$(REMOTE)" "refs/tags/$$tag" >/dev/null 2>&1; then \
		echo "Error: remote tag $$tag already exists; use rewrite-release-tag only for explicit recovery" >&2; \
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
	git tag --annotate "$$tag" --message "Release $$tag"; \
	git push --atomic "$(REMOTE)" \
		"HEAD:refs/heads/$(BRANCH)" \
		"refs/tags/$$tag:refs/tags/$$tag"; \
	echo "Released $$tag"

# Emergency recovery only: rewrite the current VERSION tag without force-pushing
# the release branch. The exact remote tag object is protected by force-with-lease.
rewrite-release-tag: test
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
	if [[ "$${CONFIRM_REWRITE_TAG:-}" != "$$tag" ]]; then \
		echo "Error: rewriting a published tag is exceptional and changes its commit" >&2; \
		echo "Repeat with: make rewrite-release-tag CONFIRM_REWRITE_TAG=$$tag" >&2; \
		exit 1; \
	fi; \
	if [[ "$$(git branch --show-current)" != "$(BRANCH)" ]]; then \
		echo "Error: tag recovery must run on branch $(BRANCH)" >&2; \
		exit 1; \
	fi; \
	if [[ -n "$$(git status --porcelain --untracked-files=all)" ]]; then \
		echo "Error: the worktree must be clean before rewriting a release tag" >&2; \
		exit 1; \
	fi; \
	if ! git remote get-url "$(REMOTE)" >/dev/null 2>&1; then \
		echo "Error: git remote $(REMOTE) does not exist" >&2; \
		exit 1; \
	fi; \
	git fetch --no-tags "$(REMOTE)" "refs/heads/$(BRANCH):refs/remotes/$(REMOTE)/$(BRANCH)"; \
	if ! git merge-base --is-ancestor "refs/remotes/$(REMOTE)/$(BRANCH)" HEAD; then \
		echo "Error: HEAD is not a fast-forward of $(REMOTE)/$(BRANCH)" >&2; \
		exit 1; \
	fi; \
	remote_tag_oid="$$(git ls-remote --tags "$(REMOTE)" "refs/tags/$$tag" | awk 'NR == 1 { print $$1 }')"; \
	if [[ -z "$$remote_tag_oid" ]]; then \
		echo "Error: remote tag $$tag does not exist; use make release for a new tag" >&2; \
		exit 1; \
	fi; \
	git tag --force --annotate "$$tag" --message "Release $$tag (rewritten)"; \
	git push --atomic \
		--force-with-lease="refs/tags/$$tag:$$remote_tag_oid" \
		"$(REMOTE)" \
		"HEAD:refs/heads/$(BRANCH)" \
		"refs/tags/$$tag:refs/tags/$$tag"; \
	echo "Rewrote $$tag; $(BRANCH) was pushed without force"

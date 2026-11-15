# AGENTS.md

These instructions apply to the entire repository.

## Project overview

`http_ssh_proxy` is an HTTP forward proxy that sends outbound HTTP requests and
HTTPS `CONNECT` tunnels through one managed SSH connection. The canonical Go
module is `github.com/hightemp/http_ssh_proxy` and the executable entry point is
`cmd/http_ssh_proxy`.

The project treats request cancellation, bounded resource use, SSH host-key
verification, proxy authentication, and graceful shutdown as correctness and
security requirements. Do not weaken them for convenience.

## Repository layout

- `cmd/http_ssh_proxy`: CLI flags, config loading, signals, and process exit.
- `internal/app`: dependency wiring and application lifecycle.
- `internal/config`: strict YAML loading, defaults, and validation.
- `internal/proxy`: HTTP forwarding, authentication, headers, CONNECT, and transfer lifecycle.
- `internal/sshmanager`: shared SSH client, verification, reconnect, keepalive, and dialing.
- `internal/buildinfo`: version, commit, build time, and runtime metadata.
- `internal/logutil`: shared close/error logging helpers.
- `.github/workflows`: CI, lint, and cross-platform release automation.
- `Makefile`: the supported local build, verification, and release interface.

If a `.codegraph/` directory exists, use `codegraph explore` before text search
when locating symbols or understanding call paths. Otherwise use `rg` and
`rg --files`.

## Working rules

- Preserve user changes and unrelated untracked files. Inspect `git status`
  before editing and before staging.
- Use `gofmt` for Go files and keep shell scripts compatible with Bash strict
  mode (`set -euo pipefail`).
- Keep `cmd/http_ssh_proxy/main.go` thin. Put reusable behavior in the relevant
  `internal` package.
- Pass `context.Context` through blocking network operations and return promptly
  on cancellation.
- Give every goroutine an explicit owner, termination condition, and bounded
  lifetime. Avoid background goroutine leaks.
- Wrap errors with `%w` when callers need to inspect the cause. Do not use
  `panic` or `log.Fatal` outside the executable boundary.
- Document exported identifiers. Prefer small interfaces at package boundaries
  and concrete types inside packages.
- Add or update tests next to changed code. Prefer table-driven tests and local
  in-process servers over external network dependencies.
- Timing-sensitive tests must have enough scheduling headroom to remain stable
  under `-race`; never hide flakes with arbitrary retries.
- Do not add dependencies unless they materially simplify the implementation.
  Run module checks after dependency changes.

## Security invariants

- SSH server identity must always be verified by exactly one of OpenSSH
  `known_hosts` or a pinned SHA256 fingerprint. Never introduce an insecure
  host-key callback.
- Never log passwords, private keys, authorization headers, or complete URLs
  containing sensitive query data.
- Never pass credentials in process arguments when a protected file or stdin is
  available.
- Preserve context cancellation during SSH dial/handshake and HTTP forwarding.
- Preserve HTTP request semantics and remove hop-by-hop headers in both
  directions.
- CONNECT tunnels must retain TCP half-close behavior, idle deadlines, resource
  limits, and graceful-shutdown tracking.
- The shared `max_connections` limit applies to both ordinary upstream
  connections and CONNECT tunnels.
- Treat configuration, SSH keys, and TLS keys as secrets. Never commit local
  credentials or generated private keys.

## Files that must not be committed

The following root files are intentionally ignored and must remain untracked:

- `config.yaml` — local configuration and credentials.
- `server.key` and `server.pem` — locally generated TLS material.
- `coverage.out`, `http_ssh_proxy`, and `http_ssh_proxy_static` — generated output.

Do not stage unrelated review, audit, editor, or local-environment files merely
because they appear in the worktree.

## Required verification

Use the smallest relevant test while iterating, then run the full gate before a
commit that changes behavior:

```bash
gofmt -w <changed-go-files>
make check
GOTOOLCHAIN="$(go env GOVERSION)" \
  go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
```

`make check` performs readonly module checks, `go vet`, race-enabled coverage,
the 90% repository coverage gate, and `govulncheck`. If `govulncheck` is not on
`PATH`, install the pinned scanner using the project toolchain:

```bash
GOTOOLCHAIN="$(go env GOVERSION)" \
  go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
```

Additional commands:

```bash
make test          # race-enabled unit and integration tests
make coverage      # fresh atomic coverage profile and 90% gate
make fuzz          # short smoke runs for both fuzz targets
make module-check  # verify, tidy diff, and readonly dependency graph
make build         # metadata-bearing local binary
```

For shell or workflow changes, also run:

```bash
bash -n generate_keys.sh test.sh install_service.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

Do not run `install_service.sh`, mutate systemd, generate replacement keys, or
contact real proxy/SSH targets unless the user explicitly requests it.

## Versioning and releases

- `VERSION` is the single source of the release version.
- Preserve linker metadata (`Version`, `Commit`, and `BuildTime`) in every new
  build path. `http_ssh_proxy -version` must work without configuration.
- Release archives target Linux amd64/arm64/armv7, macOS amd64/arm64, and
  Windows amd64/arm64.
- The release workflow must retain native Linux/macOS/Windows smoke tests,
  checksums, SPDX SBOM generation, build provenance, and SBOM attestations.
- Pin release workflow actions to immutable full commit SHAs.
- Never create commits, tags, GitHub releases, or push remote refs unless the
  user explicitly requests those external changes.

For a normal release, first commit all release contents, change only `VERSION`,
then use:

```bash
make release
```

Normal release tags are immutable and the branch must never be force-pushed.
Only when the user explicitly requests recovery of an already published version
may the dedicated tag-only path be used:

```bash
make rewrite-release-tag CONFIRM_REWRITE_TAG=vX.Y.Z
```

This recovery command may force-with-lease the named tag only. Never replace it
with a broad `git push --force` or force-push `main`.

## Completion checklist

Before handing work back:

1. Run the relevant tests and the full gate in proportion to the change.
2. Run `git diff --check`.
3. Review `git status --short` and the staged file list.
4. Confirm no ignored secrets, audit files, or unrelated user files are staged.
5. Report what changed, what was verified, and whether anything was committed or pushed.

# Current Task

Date: 2026-05-18

Branch: `feature/reality-tcp-brutal-yaml`

## Status

Task implementation is complete and verified. No commit has been made.

The workspace still has pre-existing/unrelated untracked paths such as `.opencode/` and `target/`; they were left untouched.

## Completed Changes

- Created development branch from `main`: `feature/reality-tcp-brutal-yaml`.
- Added YAML config support to `anytls-server` via `--config`.
- Added `anyreality.yaml` example based on `rust-rewrite-no-reality`.
- Added `deploy/systemd/anytls-anyreality.service` for the Go server binary.
- Added deployment parameter generation under `anytls-server generate ...`:
  - `reality-keypair`
  - `rand --hex` / `rand --base64`
  - `reality-server-config` to print Reality YAML, URI, client JSON, and deployment helper commands.
- Integrated Reality transport support:
  - Client side uses sing-box `NewRealityClient` with uTLS fingerprint support.
  - Server side uses the sing-box/uTLS Reality implementation path while preserving multiple `server_names` from YAML.
  - Default builds without `with_utls` still compile and return a clear error if Reality is used.
- Integrated TCP Brutal on the anytls TCP transport:
  - Linux sets `TCP_CONGESTION=brutal`.
  - Linux sets `TCP_BRUTAL_PARAMS=23301` with rate and `cwnd_gain`.
  - Server YAML uses `down_mbps` as the server send rate.
- Implemented `/etc/gai.conf` `precedence` parsing in the system dialer and sorts resolved IPs accordingly.
- Updated client URL/flag support for Reality:
  - `security=reality`
  - `pbk`
  - `sid`
  - `fp`
- Updated `docs/uri_scheme.md` with Reality URI query parameters and TCP Brutal configuration notes.
- Updated GitHub/release config:
  - GoReleaser v2 config builds `anytls-client` and `anytls-server`.
  - Client/server release builds include `-tags=with_utls`.
  - Release uploads standalone Linux binaries, archives, `anyreality.yaml`, and `deploy/systemd/anytls-anyreality.service`.
  - Added `.github/workflows/release.yml`.
- Added tests for YAML config parsing, GAI precedence, TCP Brutal config/param layout, and Reality helper decoding.
- Updated `cmd/client/inbound.go` for newer `github.com/sagernet/sing` handler interfaces after dependency upgrade.
- Updated `.opencode/skills/deploy-anyreality/SKILL.md` from Rust deployment instructions to Go deployment instructions.
- Deployed local Go build to `45.143.129.143` using the previous Rust config values under `/opt/anytls`:
  - `/opt/anytls/anytls-server`
  - `/opt/anytls/anyreality.yaml`
  - `/etc/systemd/system/anytls-anyreality.service`

## Key Decisions

- Kept the existing two-binary structure: `anytls-client` and `anytls-server`.
- Did not port the Rust implementation back into Go.
- Reused sing-box/uTLS Reality logic instead of maintaining a separate Reality protocol implementation.
- Used a build tag boundary:
  - `with_utls` enables Reality implementation.
  - no tag keeps normal TLS builds working with a Reality stub.
- Applied TCP Brutal directly to the underlying anytls TCP connection instead of introducing sing-mux.
- Used `down_mbps` for server-side TCP Brutal send rate, matching the Rust reference branch behavior.
- Preserved resolver order when `/etc/gai.conf` has no active `precedence` rules.

## Verification Already Run

- `go test ./...`
- `go test -tags with_utls ./...`
- `go build -o /tmp/opencode/anytls-client ./cmd/client`
- `go build -o /tmp/opencode/anytls-server ./cmd/server`
- `go build -tags with_utls -o /tmp/opencode/anytls-client-utls ./cmd/client`
- `go build -tags with_utls -o /tmp/opencode/anytls-server-utls ./cmd/server`
- `git diff --check`
- Re-ran after URI docs update: `go test ./...`, `go test -tags with_utls ./...`, `git diff --check`
- Generator verification: `go run ./cmd/server generate reality-keypair`, `go run ./cmd/server generate rand --hex 8`, `go run ./cmd/server generate reality-server-config ...`
- Release verification: `go run github.com/goreleaser/goreleaser/v2@latest check`, `go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean`
- Remote Go deployment verification on `45.143.129.143`: `systemctl is-active anytls-anyreality.service`, `systemctl is-enabled anytls-anyreality.service`, `ss -ltnp | grep :38746`, `journalctl -u anytls-anyreality.service -n 30 --no-pager`, `/opt/anytls/anytls-server generate reality-server-config ...`

## Important Files

- `.goreleaser.yaml`
- `anyreality.yaml`
- `deploy/systemd/anytls-anyreality.service`
- `docs/uri_scheme.md`
- `cmd/client/main.go`
- `cmd/client/inbound.go`
- `cmd/server/generate.go`
- `cmd/server/generate_test.go`
- `cmd/server/main.go`
- `cmd/server/config.go`
- `cmd/server/config_test.go`
- `cmd/server/inbound_tcp.go`
- `cmd/server/myserver.go`
- `proxy/reality/reality.go`
- `proxy/reality/reality_with_utls.go`
- `proxy/reality/reality_stub.go`
- `proxy/reality/reality_with_utls_test.go`
- `proxy/tcpbrutal/tcpbrutal.go`
- `proxy/tcpbrutal/tcpbrutal_linux.go`
- `proxy/tcpbrutal/tcpbrutal_other.go`
- `proxy/tcpbrutal/tcpbrutal_test.go`
- `proxy/tcpbrutal/tcpbrutal_linux_test.go`
- `proxy/system_dialer.go`
- `proxy/system_dialer_test.go`
- `go.mod`
- `go.sum`
- `.github/workflows/release.yml`
- `.opencode/skills/deploy-anyreality/SKILL.md`

## Pending / Follow-Up

- Optionally run an end-to-end Reality connection test against a real server config.
- Optionally validate TCP Brutal at runtime on a Linux host with the `brutal` congestion module installed.
- Optionally commit the changes after reviewing the final diff.

## Suggested Next Commands

- Inspect status: `git status --short --branch`
- Review diff: `git diff`
- Re-run default tests: `go test ./...`
- Re-run Reality-tag tests: `go test -tags with_utls ./...`
- Build release-tag binaries manually: `go build -tags with_utls ./cmd/client && go build -tags with_utls ./cmd/server`
- Commit when ready: `git add .goreleaser.yaml .github AGENTS.md anyreality.yaml deploy cmd proxy go.mod go.sum docs/current-task.md docs/uri_scheme.md .opencode/skills/deploy-anyreality/SKILL.md && git commit -m "add reality tcp brutal yaml support"`

# AGENTS.md

This file captures durable project context for future coding sessions.

## Project Context

- This repository is the Go reference implementation of the AnyTLS proxy protocol.
- The project currently keeps separate binaries under `cmd/client` and `cmd/server`.
- Deployment helper commands are integrated into `anytls-server generate ...`.
- `rust-rewrite-no-reality` is a reference branch for YAML schema, systemd deployment examples, TCP Brutal behavior, and `/etc/gai.conf` precedence handling. Do not port the Rust implementation directly; use it only as behavior reference.
- `docs/current-task.md` contains the latest handoff snapshot for the in-progress Reality/TCP Brutal/YAML work.
- The worktree may contain unrelated untracked paths such as `.opencode/` and `target/`. Leave them untouched unless explicitly asked.

## Architecture Notes

- `cmd/client` implements the local SOCKS/HTTP inbound and opens AnyTLS streams to the remote server.
- `cmd/server` accepts the AnyTLS transport, authenticates the password hash, reads destination metadata, and proxies TCP or UoT traffic outbound.
- `proxy/session` implements AnyTLS multiplexed sessions and streams.
- `proxy/padding` implements record padding schemes.
- `proxy/system_dialer.go` is the central outbound TCP dialer and now handles `/etc/gai.conf` `precedence` sorting for resolved IP addresses.
- `proxy/reality` isolates Reality support behind build tags:
  - `with_utls` enables the actual Reality implementation.
  - default builds compile a stub that returns a clear error if Reality is requested.
- `proxy/tcpbrutal` isolates TCP Brutal socket options behind OS build tags:
  - Linux applies `TCP_CONGESTION=brutal` and `TCP_BRUTAL_PARAMS=23301`.
  - non-Linux builds return an explicit unsupported error.

## Key Decisions

- Preserve the existing two-binary layout: `anytls-client` and `anytls-server`.
- Reality should reuse sing-box/uTLS implementation paths instead of maintaining an independent protocol implementation.
- The release build should include `-tags=with_utls` so Reality is available in distributed artifacts.
- Default no-tag builds should still compile and support normal TLS mode.
- TCP Brutal is applied directly to the underlying AnyTLS TCP transport, not through sing-mux.
- In server YAML, `tcp_brutal.down_mbps` is the server send rate; this matches the Rust reference branch behavior.
- Preserve DNS resolver order unless `/etc/gai.conf` has active `precedence` rules.

## Configuration Notes

- Server YAML entry point is `anytls-server --config <path>`.
- Deployment parameter generation entry point is `anytls-server generate reality-server-config ...`.
- Example Reality server config lives at `anyreality.yaml`.
- Example systemd unit lives at `deploy/systemd/anytls-anyreality.service`.
- Client Reality parameters can come from flags or AnyTLS URI query values:
  - `security=reality`
  - `pbk`
  - `sid`
  - `fp`
  - `sni`
- Reality requires `with_utls` at build time.
- TCP Brutal requires a Linux host with the `brutal` congestion control module available.

## Dependency Notes

- The code depends on newer `github.com/sagernet/sing` handler interfaces. Client inbound code should use `HandleConnectionEx` variants and implement `NewConnectionEx` / `NewPacketConnectionEx` when needed.
- sing-box Reality imports can pull in large transitive dependencies.
- If `go mod tidy` or downloads fail due to sumdb/proxy issues for Sagernet modules, retry with: `GONOSUMDB=github.com/sagernet/* go mod tidy`.

## Development Conventions

- Make the smallest correct change; avoid broad rewrites.
- Use `gofmt` on edited Go files.
- Keep normal TLS mode working without build tags.
- Keep Reality-specific code behind `with_utls` where possible.
- Keep Linux-specific socket option code behind `//go:build linux`.
- Do not remove or rewrite protocol/session behavior unless tests or a concrete bug require it.
- Do not commit unless explicitly requested.

## Verification Commands

- Default tests: `go test ./...`
- Reality-tag tests: `go test -tags with_utls ./...`
- Default client build: `go build -o /tmp/opencode/anytls-client ./cmd/client`
- Default server build: `go build -o /tmp/opencode/anytls-server ./cmd/server`
- Reality client build: `go build -tags with_utls -o /tmp/opencode/anytls-client-utls ./cmd/client`
- Reality server build: `go build -tags with_utls -o /tmp/opencode/anytls-server-utls ./cmd/server`
- Whitespace check: `git diff --check`

## Important Paths

- `.goreleaser.yaml`
- `anyreality.yaml`
- `deploy/systemd/anytls-anyreality.service`
- `cmd/client/main.go`
- `cmd/client/inbound.go`
- `cmd/server/generate.go`
- `cmd/server/main.go`
- `cmd/server/config.go`
- `cmd/server/inbound_tcp.go`
- `cmd/server/myserver.go`
- `proxy/reality/`
- `proxy/tcpbrutal/`
- `proxy/system_dialer.go`
- `docs/current-task.md`

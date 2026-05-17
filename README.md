# anytls-rust release notes

## Linux release policy

For Linux servers, the preferred release asset is a statically linked musl binary:

```text
anytls-x86_64-unknown-linux-musl
```

Why:

- avoids glibc version mismatches across Debian 11+, Debian 12, Ubuntu 22.04+, and Arch Linux
- works better for direct GitHub release download deployments
- avoids coupling release compatibility to the builder host's glibc version

## Recommended server asset

Use this asset for deployment:

```text
anytls-x86_64-unknown-linux-musl
```

Do not prefer a dynamically linked `x86_64-unknown-linux-gnu` binary for release deployments unless you deliberately build on an old-enough glibc baseline.

## Suggested release assets

- `anytls-x86_64-unknown-linux-musl`
- `anyreality.yaml`
- `anytls-anyreality.service`

## Local build examples

If you have `cross`:

```bash
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target x86_64-unknown-linux-musl
```

Output:

```text
target/x86_64-unknown-linux-musl/release/anytls
```

Suggested upload name:

```text
anytls-x86_64-unknown-linux-musl
```

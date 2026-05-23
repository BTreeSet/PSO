# Proton-Singbox Orchestrator

PSO is a Rust control-plane scaffold for hydrating `sing-box` WireGuard outbounds from declarative ProtonVPN filters. It implements the Multi-Tenant Edition v2 design choices:

- Human-readable tier filters: `Free`, `Basic`, `Plus`, and `Visionary`.
- Multi-user session lookup keyed by `username`.
- Proton logical and physical server filtering by country, city, tier, features, load, status, and sort mode.
- SIGHUP-only deployment after `sing-box check -c <rendered_config.json.tmp>` succeeds.
- IP-validation health probes using Cloudflare trace with ipinfo fallback.

## Current State

This repository is a runnable foundation. PSO can fetch Proton logical topology from `/vpn/logicals`, perform SRP-based login, fork a VPN-scoped session, and cache the VPN refresh token in a headless-friendly session file. The renderer generates WireGuard key material locally for every hydrated outbound. The private key is never supplied by the user and is never sent to Proton. The `control-plane` command owns the live certificate refresh lifecycle by sending locally generated public keys to `/vpn/certificate`, atomically writing a sing-box config, and signaling sing-box with `SIGHUP`.

## Login and Session Fork

Run the Proton SRP login flow and fork the primary account session into a VPN-scoped session:

```bash
cargo run -- login \
  --username alice@example.com \
  --totp 123456
```

For noninteractive deployments, supply the password through `PSO_PROTON_PASSWORD`, `--password`, `PSO_PROTON_PASSWORD_FILE`, or `--password-file`. Add `--no-prompt` in containers so missing credentials fail fast instead of blocking for input. If Proton reports that two-factor authentication is enabled, supply `PSO_PROTON_TOTP` or `--totp`.

By default, the command stores the VPN refresh token in `vpn-session.json` and prints the current VPN-scoped token response to stdout unless `--output vpn-session.json` is supplied. In Docker, mount the session cache path on durable storage:

```bash
PSO_PROTON_PASSWORD_FILE=/run/secrets/proton_password \
PSO_VPN_SESSION_CACHE=/var/lib/pso/vpn-session.json \
cargo run -- login \
  --username alice@example.com \
  --totp 123456 \
  --no-prompt
```

When Proton requires human verification, PSO returns the verification challenge details. Complete the challenge in a browser, then rerun the failed command with:

```bash
cargo run -- login \
  --username alice@example.com \
  --human-verification-token replace-with-token
```

On later boots, refresh the cached VPN session without replaying the password flow:

```bash
cargo run -- refresh-vpn-token \
  --username alice@example.com \
  --session-cache-file /var/lib/pso/vpn-session.json
```

## Render a Config

```bash
cp config.template.example.json config.template.json
cargo run -- refresh-vpn-token --username alice@example.com --output vpn-session.json
PSO_PROTON_ACCESS_TOKEN='replace-with-vpn-access-token' cargo run -- fetch-logicals \
  --output proton-logicals.json \
  --cache proton-logicals.cache.json
cargo run -- render \
  --template config.template.json \
  --topology proton-logicals.json \
  --output rendered.config.json.tmp \
  --session alice@example.com:Plus \
  --session bob_free_tier@example.com:Free \
  --dry-run
```

For offline development, `proton-logicals.example.json` contains a tiny fixture with the same top-level `LogicalServers` shape returned by `/vpn/logicals`.

`fetch-logicals` retries transient Proton API failures. If the endpoint is temporarily unavailable and a cache file exists, PSO writes the cached topology to the requested output path so a short `/vpn/logicals` outage does not erase the last known usable server set. Pass `--no-cache-fallback` when you need strict fresh topology.

Remove `--dry-run` to validate the result with `sing-box check`. Add `--active-config /path/to/config.json --singbox-pid <pid>` to atomically replace the active config and send `SIGHUP`.

## Run the Control Plane

```bash
PSO_PROTON_ACCESS_TOKEN='replace-with-access-token' cargo run -- control-plane \
  --active-config /etc/sing-box/config.json \
  --endpoint 203.0.113.10:443 \
  --peer-public-key replace-with-peer-public-key \
  --outbound-tag proton-wg
```

The command discovers `sing-box` by process name when `--singbox-pid` is omitted. On every successful certificate response, PSO writes the generated WireGuard outbound atomically and sends `SIGHUP`. On refresh failure, it schedules the next attempt at the midpoint between now and certificate expiration, with a 30 second minimum delay and a four-attempt limit before rotating local key material.

## Health Probes

Acquire the raw host IP baseline:

```bash
cargo run -- baseline
```

Probe once through the default network path or through a proxy exposed by a specific outbound:

```bash
cargo run -- probe --raw-ip 198.51.100.1
cargo run -- probe --raw-ip 198.51.100.1 --proxy-url socks5h://127.0.0.1:1081
```

If the returned probe IP equals the raw baseline, PSO reports `Leaking`. If both Cloudflare and ipinfo fail, it reports `Dead`. Any non-baseline IP is treated as `Healthy`.

## CI

GitHub Actions runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` on pushes and pull requests. The container job builds `linux/amd64` and `linux/arm64` images with Docker Buildx and publishes to GHCR for non-PR runs. The runtime image is Alpine-based and bundles `sing-box` by copying `/usr/local/bin/sing-box` from `ghcr.io/sagernet/sing-box:latest` into the PSO image.

Dependency review notes live in `docs/dependencies.md`. Dependabot tracks Cargo, GitHub Actions, and Docker updates weekly.
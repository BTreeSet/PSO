# Proton-Singbox Orchestrator

PSO is a Rust control-plane scaffold for hydrating `sing-box` WireGuard outbounds from declarative ProtonVPN filters. It implements the Multi-Tenant Edition v2 design choices:

- Human-readable tier filters: `Free`, `Basic`, `Plus`, and `Visionary`.
- Multi-user session lookup keyed by `username`.
- Proton logical and physical server filtering by country, city, tier, features, load, status, and sort mode.
- SIGHUP-only deployment after `sing-box check -c <rendered_config.json.tmp>` succeeds.
- IP-validation health probes using Cloudflare trace with ipinfo fallback.

## Current State

This repository is a runnable foundation. PSO can fetch Proton logical topology from `/vpn/logicals`, perform SRP-based login, fork a VPN-scoped session, and cache the VPN refresh token in the OS keyring. The renderer generates WireGuard key material locally for every hydrated outbound. The private key is never supplied by the user and is never sent to Proton. The `control-plane` command owns the live certificate refresh lifecycle by sending locally generated public keys to `/vpn/certificate`, atomically writing a sing-box config, and signaling sing-box with `SIGHUP`.

## Login and Session Fork

Run the Proton SRP login flow and fork the primary account session into a VPN-scoped session:

```bash
cargo run -- login \
  --username alice@example.com \
  --totp 123456
```

If `--password` is omitted, PSO prompts without echoing input. If Proton reports that two-factor authentication is enabled and `--totp` is omitted, PSO prompts for the TOTP code. The command stores the VPN refresh token in the OS keyring under the username and prints the current VPN-scoped token response to stdout unless `--output vpn-session.json` is supplied.

When Proton requires human verification, PSO returns the verification challenge details. Complete the challenge in a browser, then rerun the failed command with:

```bash
cargo run -- login \
  --username alice@example.com \
  --human-verification-token replace-with-token
```

On later boots, refresh the cached VPN session without replaying the password flow:

```bash
cargo run -- refresh-vpn-token --username alice@example.com
```

## Render a Config

```bash
cp config.template.example.json config.template.json
cargo run -- refresh-vpn-token --username alice@example.com --output vpn-session.json
PSO_PROTON_ACCESS_TOKEN='replace-with-vpn-access-token' cargo run -- fetch-logicals \
  --output proton-logicals.json
cargo run -- render \
  --template config.template.json \
  --topology proton-logicals.json \
  --output rendered.config.json.tmp \
  --session alice@example.com:Plus \
  --session bob_free_tier@example.com:Free \
  --dry-run
```

For offline development, `proton-logicals.example.json` contains a tiny fixture with the same top-level `LogicalServers` shape returned by `/vpn/logicals`.

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

GitHub Actions runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` on pushes and pull requests.
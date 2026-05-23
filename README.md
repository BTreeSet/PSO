# Proton-Singbox Orchestrator

PSO is a Rust control-plane scaffold for hydrating `sing-box` WireGuard outbounds from declarative ProtonVPN filters. It implements the Multi-Tenant Edition v2 design choices:

- Human-readable tier filters: `Free`, `Basic`, `Plus`, and `Visionary`.
- Multi-user session lookup keyed by `username`.
- Proton logical and physical server filtering by country, city, tier, features, load, status, and sort mode.
- SIGHUP-only deployment after `sing-box check -c <rendered_config.json.tmp>` succeeds.
- IP-validation health probes using Cloudflare trace with ipinfo fallback.

## Current State

This repository is a runnable foundation, not a complete Proton production client yet. The renderer accepts a local Proton logical topology JSON file and uses a static WireGuard private key supplied through `PSO_WG_PRIVATE_KEY` or `--private-key`. The production next step is replacing `StaticProvisioner` with a Proton API implementation that rotates refresh tokens and requests `/vpn/certificate` per selected physical node.

## Render a Config

```bash
cp config.template.example.json config.template.json
cp proton-logicals.example.json proton-logicals.json
PSO_WG_PRIVATE_KEY='replace-with-private-key' cargo run -- render \
  --template config.template.json \
  --topology proton-logicals.json \
  --output rendered.config.json.tmp \
  --session alice@example.com:Plus \
  --session bob_free_tier@example.com:Free \
  --dry-run
```

Remove `--dry-run` to validate the result with `sing-box check`. Add `--active-config /path/to/config.json --singbox-pid <pid>` to atomically replace the active config and send `SIGHUP`.

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
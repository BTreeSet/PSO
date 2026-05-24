# Roadmap

This roadmap lists technical directions that fit PSO's goal: automatic `sing-box` orchestration from declarative configuration and provider state. Items here are not implemented unless the README or code says so.

## Near Term

- State directory ownership: keep generated and persistent runtime state under one opaque state directory. SQLite owns VPN session state, certificate metadata, runtime events, and health history; raw topology remains as JSON for provider troubleshooting.
- Account lifecycle hardening: add richer batch account maintenance flows, clearer human-verification retry handling, and more explicit session-expiry observability.
- Multi-endpoint daemon loop hardening: extend the current supervisor with server reselection policy, per-endpoint backoff tuning, and graceful shutdown.
- Health-driven recovery: combine Cloudflare/ipinfo probe results with endpoint certificate state to reselect servers when a refreshed endpoint remains dead or leaking.
- Mock integration tests: add a local mock Proton API and a fake sing-box process/signal target for deterministic CI coverage.

## Container Operation

- Runtime entrypoint: add a Docker-first command that performs login/refresh, topology fetch, render, sing-box startup, and control-loop execution from one process model.
- Example compose files: document mounted config files, mounted state directory, optional password-file input, required capabilities, and expected ports.
- State permissions: define owner, mode, and migration behavior for state files written by the container.
- Image provenance: publish SBOM/provenance attestations alongside GHCR images.

## Provider Abstraction

- Dynamic provider APIs: extend the current Proton-native and static WireGuard catalog model with provider-specific API implementations where providers expose enough surface for local key registration, server topology, and reliable tunnel provisioning.
- Provider catalog imports: add import helpers for provider-issued WireGuard metadata formats without accepting private keys from config.
- Provider chaining: model chained outbounds as explicit graph edges in declarative config rather than implicit routing side effects.
- Mixed-provider health: track health per hop for chained routes so recovery can identify which provider or outbound failed.

## Configuration Model

- Declarative schema: publish a versioned schema for `config.template.json` and PSO-specific filter fields.
- Validation command: add a command that validates templates, sessions, filters, state directory access, and sing-box availability without changing runtime state.
- Policy groups: support reusable filter groups for countries, tiers, features, and provider preferences.
- Safer output staging: keep generated configs in state until validation succeeds, then atomically replace the active config.

## Security and Supply Chain

- Advisory scanning: add RustSec advisory checks to CI once the scanner is available in the build environment.
- Dependency review gate: keep direct features minimal and fail CI on unexpected duplicate major versions where practical.
- Secret handling: avoid logging tokens, passwords, private keys, and certificate bodies; add tests for redaction on error paths.
- State encryption option: evaluate file-level encryption for state directories in environments where mounted storage is not already protected.

# Dependency Review

This project is pre-alpha, so dependency choices favor current APIs, small feature sets, and container-friendly runtime behavior over backwards compatibility.

## Direct Dependency Inventory

The current direct runtime dependency graph was captured with `cargo tree -e normal --depth 1` after `cargo update`:

- `anyhow 1.0.102`: error context for CLI/control-plane flows.
- `base64 0.22.1`: WireGuard key and Proton payload encoding.
- `clap 4.6.1`: CLI parser with env-var support.
- `hex 0.4.3`: hexadecimal encoding for render fingerprints and opaque username state keys.
- `libc 0.2.186`: POSIX `SIGHUP` signaling.
- `parking_lot 0.12.5`: in-memory session store locking.
- `proton-srp 0.8.2` from `proton_public`: maintained internal Proton SRP client implementation, including signed-modulus verification through its transitive OpenPGP stack.
- `rand_core 0.6.4`: RNG trait version required by `x25519-dalek`.
- `reqwest 0.13.3`: Proton HTTP client, with only `json`, `query`, and `rustls` features enabled.
- `rpassword 7.5.3`: hidden password/TOTP prompt for rare interactive CLI runs.
- `rusqlite 0.39.0`: SQLite state database for Proton auth sessions, runtime events, and health history, with bundled SQLite for predictable Alpine/container builds.
- `serde 1.0.228`, `serde_json 1.0.150`: API/config serialization.
- `sha1 0.11.0`: RFC 6238 TOTP code derivation from long-term 2FA secrets.
- `sha2 0.11.0`: hashing for render/state digests and Proton helper code outside the SRP crate.
- `sysinfo 0.39.2`: sing-box process discovery.
- `tempfile 3.27.0`: atomic config write support.
- `tokio 1.52.3`: async runtime, timers, process, signal, and supervisor channel/mutex support.
- `tracing 0.1.44`, `tracing-subscriber 0.3.23`: structured logging.
- `x25519-dalek 2.0.1`: local WireGuard X25519 key generation.

## Held Dependency

`cargo update --dry-run --verbose` reports only one direct dependency behind latest:

- `rand_core 0.6.4` is held because `x25519-dalek 2.0.1` uses the `rand_core 0.6` RNG traits. Upgrading PSO's direct `rand_core` to `0.10` would make `StaticSecret::random_from_rng` incompatible. Keep this pinned until `x25519-dalek` publishes a compatible RNG-trait update or PSO moves key generation behind a different crypto provider.

## Duplicate Versions

`cargo tree -d` now reports several duplicate crypto support crates after adopting `proton-srp`:

- `block-buffer`/`digest`/`cpufeatures` are split between PSO's direct `sha1`/`sha2` 0.11 stack and `proton-srp -> pgp`'s `sha1`/`sha2` 0.10 stack.
- `getrandom 0.2.17` arrives through `rand_core 0.6.4` and `proton-srp`; `getrandom 0.3.4` arrives through `proton-srp -> bcrypt 0.17.1`; `getrandom 0.4.2` still arrives through `tempfile 3.27.0`.
- `const-oid` and `crypto-common` also duplicate for the same reason.

This is an accepted temporary cost of reusing Proton's maintained SRP implementation instead of carrying custom SRP math locally. Revisit when the internal SRP stack converges on newer crypto support crates or when PSO can consolidate its direct digest requirements.

## Supply Chain Posture

- `Cargo.lock` is committed and Docker builds use `cargo build --release --locked`.
- The workspace `.cargo/config.toml` registers the internal `proton_public` sparse index so builds can resolve `proton-srp`; CI and release builders must have access to `https://rust-registry.proton.me/index/`.
- `proton-srp` now owns Proton SRP modulus verification; PSO no longer carries a parallel in-tree implementation of the SRP math and signed-modulus parsing.
- `reqwest` is built with `default-features = false` and only the features PSO uses: `json`, `query`, `rustls`.
- Native OpenSSL is avoided in the PSO binary; the Alpine runtime installs only `bash`, `tzdata`, `ca-certificates`, and `nftables` plus bundled `sing-box`.
- Desktop keyring integration was removed. Headless deployments use `pso.sqlite3` plus explicit files under the PSO state directory, typically backed by a mounted Docker volume.
- `keyring` was removed to avoid desktop secret-service assumptions and to reduce platform-specific transitive dependencies.
- `reqwest 0.13` with the `rustls` feature currently pulls `aws-lc-rs`/`aws-lc-sys`, which adds a native cryptography build dependency. This is the upstream default provider path for current reqwest/rustls. Monitor this dependency in CI and review if a pure-Rust provider option becomes viable without runtime provider setup.
- Docker images are built multi-arch in CI and publish to GHCR only from non-PR runs.
- Dependabot tracks Cargo, GitHub Actions, and Docker dependency updates weekly.

## Local Review Commands

```bash
cargo update --dry-run --verbose
cargo tree -e normal --depth 1
cargo tree -d
cargo tree -i rand_core@0.6.4
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

`cargo audit` is not installed in the current workspace image. Add RustSec advisory scanning to CI before production release if it is not supplied by the surrounding platform.

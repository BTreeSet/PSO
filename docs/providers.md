# Provider Model

PSO is a WireGuard-first `sing-box` orchestrator. Provider support is split into three modes:

- `dynamic-api`: PSO talks to a provider API, owns refresh state, and updates endpoint state automatically. Proton is implemented in this mode.
- `dynamic-catalog`: PSO fetches a public WireGuard server catalog, selects servers, generates and persists local WireGuard keys, records health, and refreshes metadata during `render` and `run`. Mullvad, IVPN, and Surfshark are implemented in this mode.
- `static-wireguard-catalog`: the operator supplies provider-issued WireGuard endpoint metadata in `pso.config.json`; PSO selects servers, generates and persists local WireGuard keys, renders sing-box endpoints, records health, and can reselect among configured servers.

This keeps provider-specific secrets and long-lived runtime data out of templates while allowing WireGuard-capable providers to be modeled without adding OpenVPN-era compatibility code.

## Built-In Provider Surface

Run:

```bash
pso providers list
pso providers list --json
```

The WireGuard-capable provider surface tracked from Gluetun research is:

| Provider | PSO mode | Notes |
| --- | --- | --- |
| Proton | dynamic API | Native SRP login, stored auth-session refresh, topology fetch, persistent certificate registration and expiry extension, local key generation, browser-style session keepalive. |
| AirVPN | static catalog | Declare endpoint, non-default WireGuard port, peer public key, pre_shared_key, assigned address, and filters. |
| CyberGhost | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| FastestVPN | static catalog | Declare provider-issued WireGuard endpoint metadata. |
| IVPN | dynamic catalog or static catalog | Public server metadata can be refreshed automatically; declare alternate WireGuard ports or pinned fallback servers when needed. |
| Mullvad | dynamic catalog or static catalog | Public relay metadata can be refreshed automatically and supports WireGuard peer `reserved` bytes. |
| NordVPN | static catalog | Declare NordLynx/WireGuard endpoint metadata. |
| Perfect Privacy | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| Private Internet Access | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. Automatic provider-side port forwarding is not implemented yet. |
| PrivateVPN | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. Automatic provider-side port forwarding is not implemented yet. |
| PureVPN | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| Surfshark | dynamic catalog or static catalog | Public WireGuard cluster metadata can be refreshed automatically; static catalogs can pin metadata locally. |
| TorGuard | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| VPNUnlimited | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| VyprVPN | static catalog | Declare provider-issued WireGuard metadata through the shared static catalog schema. |
| Windscribe | static catalog | Declare provider-specific WireGuard ports and peer public keys from the provider catalog. |
| Custom | static catalog | Use for any provider with known WireGuard endpoint metadata. |

Providers that only expose OpenVPN are intentionally not modeled because PSO renders sing-box WireGuard endpoints only.

## Catalog Schema

Dynamic or static WireGuard providers live under `providers.wireguard` in `pso.config.json`:

```json
{
  "providers": {
    "wireguard": [
      {
        "name": "mullvad",
        "source": { "type": "mullvad_api" },
        "default_port": 51820,
        "local_address": ["10.64.10.2/32"],
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "persistent_keepalive_interval": 25
      }
    ]
  }
}
```

`source` defaults to `{"type":"static"}`. Built-in dynamic sources are `mullvad_api`, `ivpn_api`, and `surfshark_api`. For dynamic catalogs, `servers` is optional and acts as a local fallback when the public API is unavailable or when you want to pin known-good metadata. `local_address` is still the tunnel address assigned by the provider for the local WireGuard identity; it can be declared at provider, server, or template-endpoint level. `pre_shared_key` can also be declared at provider, server, or template-endpoint level and is injected into the rendered sing-box peer object when present. PSO does not accept a WireGuard private key from config; it generates and persists local private/public key material in SQLite. If a provider requires public-key registration, register the public key PSO records for the endpoint out of band or extend PSO with a provider-specific dynamic API implementation.

Public provider catalogs often expose provider-native location labels such as `Sweden` instead of ISO country codes. Template filters should match the actual catalog values that the provider returns.

## Template Endpoints

A provider endpoint references the catalog by name:

```json
{
  "type": "wireguard",
  "tag": "mullvad-se-stockholm",
  "provider": "mullvad",
  "filter": {
    "country": ["Sweden"],
    "city": "Stockholm",
    "status": 1,
    "sort_by": "name_asc"
  }
}
```

Supported filter fields are `server`, `country`, `city`, `region`, `features`, `max_load`, `status`, and `sort_by` (`load_asc` or `name_asc`). On unhealthy probes, PSO attempts to reselect the next matching server when more than one candidate exists. For dynamic catalogs, matching is done against the provider's published country, city, and region strings.

Providers that require a WireGuard `pre_shared_key` can also declare it directly on the template endpoint:

```json
{
  "type": "wireguard",
  "tag": "airvpn-eu-1",
  "provider": "airvpn",
  "pre_shared_key": "replace-with-provider-pre-shared-key",
  "filter": {
    "server": "airvpn-eu-1"
  }
}
```

Proton endpoints remain dynamic and use the Proton-specific filter model:

```json
{
  "type": "wireguard",
  "tag": "proton-p2p-nl",
  "provider": "proton",
  "username": "alice@example.com",
  "filter": {
    "country": ["NL"],
    "tier": "Plus",
    "features": { "p2p": true }
  }
}
```

`username` references a configured entry in `auth.proton.users`. One active Proton endpoint should map to one configured Proton username so the operator can scale out across several Proton identities cleanly.

PSO's Proton dynamic API path mirrors the browser capture more closely than the older session-only flow: `core/v4/auth/info` uses `Intent: Auto`, `vpn/v1/certificate` uses persistent-mode request bodies, `vpn/v1/certificate/all?Mode=persistent&Offset=0&Limit=51` is available for inspection, and the optional `run.session_keepalive_interval_secs` loop polls `auth/v4/sessions` with authenticated access tokens. Certificate state persists a profile identifier so expiry extension can target known profiles efficiently, preferring client public key matches and falling back to assigned IP plus endpoint correlation.

Proton can also require human verification during login. When that happens, PSO opens the `verify.proton.me` challenge URL, prompts for the resolved verification token in interactive terminals, and accepts the same token through `--human-verification-token` or `PSO_PROTON_HUMAN_VERIFICATION_TOKEN` for headless runs.

If you need to copy the token manually, open the browser DevTools console before solving the challenge and enter `postMessage = console.log`. When the CAPTCHA succeeds, the browser prints a message shaped like `{"type":"HUMAN_VERIFICATION_SUCCESS","payload":{"token":"...","type":"captcha"}}`. Use the `payload.token` value as the resolved verification token.

## State and Rendering

All hydrated WireGuard endpoint state is written to the `wireguard_endpoint_states` SQLite table. This table includes provider name, selected server, endpoint, assigned tunnel addresses, peer allowed IPs, optional peer pre_shared_key, keepalive, optional reserved bytes, local public key, and private key. State inspection intentionally does not print private keys or pre-shared keys:

```bash
pso --state-dir /var/lib/pso state wireguard
pso --state-dir /var/lib/pso state wireguard --json
```

## sing-box Notes

PSO renders the sing-box 1.11+ WireGuard endpoint shape: `endpoints`, `address`, and `peers`. Peer domains should be paired with a `domain_resolver` in the template. `listen_port` must not be combined with `detour` for WireGuard endpoints.

PSO validates the rendered config with `sing-box check`, atomically replaces the target config, and sends SIGHUP to the configured deployment target. On sing-box 1.13.x, WireGuard endpoints are recreated on reload rather than hot-patched in place, so PSO keeps WireGuard key and endpoint state external in SQLite and treats SIGHUP as a full endpoint refresh boundary.

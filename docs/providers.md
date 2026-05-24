# Provider Model

PSO is a WireGuard-first `sing-box` orchestrator. Provider support is split into two modes:

- `dynamic-api`: PSO talks to a provider API, owns refresh state, and updates endpoint state automatically. Proton is implemented in this mode.
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
| Proton | dynamic API | Native SRP login, VPN session refresh, topology fetch, certificate registration, local key generation. |
| AirVPN | static catalog | Declare endpoint, port, peer public key, assigned address, and filters. |
| FastestVPN | static catalog | Declare provider-issued WireGuard endpoint metadata. |
| IVPN | static catalog | Declare alternate WireGuard ports where needed. |
| Mullvad | static catalog | Supports WireGuard peer `reserved` bytes. |
| NordVPN | static catalog | Declare NordLynx/WireGuard endpoint metadata. |
| Surfshark | static catalog | Declare endpoint metadata and filter by location/features. |
| Windscribe | static catalog | Declare alternate WireGuard ports where needed. |
| Custom | static catalog | Use for any provider with known WireGuard endpoint metadata. |
| CyberGhost | static catalog | Supported when provider-issued WireGuard endpoint metadata is supplied. |
| Private Internet Access | static catalog | Supported as `pia` when provider-issued WireGuard endpoint metadata is supplied. |
| PrivateVPN | static catalog | Supported when provider-issued WireGuard endpoint metadata is supplied. |
| PureVPN | static catalog | Supported when provider-issued WireGuard endpoint metadata is supplied. |
| TorGuard | static catalog | Supported when provider-issued WireGuard endpoint metadata is supplied. |
| VPN Unlimited | static catalog | Supported as `vpnunlimited` when provider-issued WireGuard endpoint metadata is supplied. |
| VyprVPN | static catalog | Supported when provider-issued WireGuard endpoint metadata is supplied. |

Providers that only expose OpenVPN are intentionally not modeled because PSO renders sing-box WireGuard endpoints only.

## Static Catalog Schema

Static providers live under `providers.wireguard` in `pso.config.json`:

```json
{
  "providers": {
    "wireguard": [
      {
        "name": "mullvad",
        "default_port": 51820,
        "local_address": ["10.64.10.2/32"],
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "persistent_keepalive_interval": 25,
        "servers": [
          {
            "id": "se-sto-wg-001",
            "name": "SE Stockholm WG 001",
            "country": "SE",
            "city": "Stockholm",
            "endpoint": "198.51.100.10",
            "public_key": "replace-with-provider-peer-public-key",
            "features": ["p2p"],
            "reserved": [0, 0, 0]
          }
        ]
      }
    ]
  }
}
```

`local_address` is the tunnel address assigned by the provider for the local WireGuard identity. It can be declared at provider, server, or template-endpoint level. PSO does not accept a WireGuard private key from config; it generates and persists local private/public key material in SQLite. If a provider requires public-key registration, register the public key PSO records for the endpoint out of band or extend PSO with a provider-specific dynamic API implementation.

## Template Endpoints

A static provider endpoint references the catalog by name:

```json
{
  "type": "wireguard",
  "tag": "mullvad-se-stockholm",
  "provider": "mullvad",
  "filter": {
    "country": ["SE"],
    "city": "Stockholm",
    "features": ["p2p"],
    "max_load": 75,
    "status": 1,
    "sort_by": "load_asc"
  }
}
```

Supported static filter fields are `server`, `country`, `city`, `region`, `features`, `max_load`, `status`, and `sort_by` (`load_asc` or `name_asc`). On unhealthy probes, PSO attempts to reselect the next matching server when more than one candidate exists.

Proton endpoints remain dynamic and use the Proton-specific filter model:

```json
{
  "type": "wireguard",
  "tag": "proton-p2p-nl",
  "provider": "proton",
  "user": "alice@example.com",
  "filter": {
    "country": ["NL"],
    "tier": "Plus",
    "features": { "p2p": true }
  }
}
```

## State and Rendering

All hydrated WireGuard endpoint state is written to the `wireguard_endpoint_states` SQLite table. This table includes provider name, selected server, endpoint, assigned tunnel addresses, peer allowed IPs, keepalive, optional reserved bytes, local public key, and private key. State inspection intentionally does not print private keys:

```bash
pso --state-dir /var/lib/pso state wireguard
pso --state-dir /var/lib/pso state wireguard --json
```

## sing-box Notes

PSO renders the sing-box 1.11+ WireGuard endpoint shape: `endpoints`, `address`, and `peers`. Peer domains should be paired with a `domain_resolver` in the template. `listen_port` must not be combined with `detour` for WireGuard endpoints.

PSO validates the rendered config with `sing-box check`, atomically replaces the target config, and sends SIGHUP to the configured deployment target. WireGuard endpoint changes are safest when that target recreates the sing-box process or otherwise reloads endpoints according to the deployed sing-box version's lifecycle behavior.

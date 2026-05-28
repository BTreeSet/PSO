# Proton API Shapes

This document records the Proton VPN browser-capture request shapes that PSO currently models.
The capture is the source of truth for these shapes; when the browser trace and earlier notes differ,
the trace wins.

## Shared Surface

- API root: `https://account.protonvpn.com/api`
- PSO normalizes legacy `/api/core/v4` values back to the API root.
- The captured browser profile uses `web-vpn-settings@5.0.336.0` and a Chrome 148 User-Agent.
- Shared browser headers include `accept: application/vnd.protonmail.v1+json`, `x-pm-appversion`, `x-pm-locale`, `accept-language`, `dnt`, `priority`, `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site`, and `sec-gpc`.
- Endpoint-specific `origin` and `referer` values are used to mirror the browser flow.

## Authentication Bootstrap

- `POST /api/auth/v4/sessions`
  - No JSON body.
  - Browser capture includes `x-enforce-unauthsession: true`.
  - `referer` is the login page.

- `POST /api/core/v4/auth/info`
  - JSON body: `{ "Username": "...", "Intent": "Auto" }` on the first pass.
  - When login retries after human verification, the same request uses `Intent: "Proton"`.
  - The request is authenticated with `x-pm-uid` and the bootstrap bearer token.

- `POST /api/core/v4/auth`
  - JSON body includes `Username`, `PersistentCookies: 1`, `ClientEphemeral`, `ClientProof`, `SRPSession`, optional `Payload`, and optional `TwoFactorCode`.
  - The browser capture sends the same browser header set as the other login calls.

- `POST /api/core/v4/auth/2fa`
  - JSON body: `{ "TwoFactorCode": "..." }`.

## Browser Session Maintenance

- `GET /api/auth/v4/sessions`
  - Authenticated with `x-pm-uid` and bearer access token.
  - No request body.
  - Used as the lightweight keepalive check in PSO.

- `PUT /api/auth/v4/sessions/local/key`
  - JSON body: `{ "Key": "<base64 X25519 public key>" }`.
  - This is the browser-session local-key registration call.

- `POST /api/auth/v4/sessions/payload`
  - JSON body includes `Payload` and `PersistentCookies: 1`.
  - The payload itself is opaque and browser-generated.

- `POST /api/auth/v4/sessions/forks`
  - JSON body includes `Payload`, `ChildClientID: "web-vpn-settings"`, and `Independent: 1`.
  - `UserCode` is optional.

- `POST /api/core/v4/auth/cookies`
  - Captured browser body: `UID`, `ResponseType: "token"`, `GrantType: "refresh_token"`, `RefreshToken`, `RedirectURI: "https://protonmail.com"`, `Persistent: 0`, and `State`.
  - The capture includes `x-pm-uid` on this request.
  - No `AccessToken` field was present in the captured body.

- `POST /api/auth/v4/refresh`
  - Upstream Go reference body: `UID`, `RefreshToken`, `ResponseType: "token"`, `GrantType: "refresh_token"`, `RedirectURI: "https://protonmail.ch"`, `State`, and optional `AccessToken`.
  - The Go reference does not include `Persistent` in this request shape.
  - PSO models this upstream refresh shape separately from the captured browser cookie body.

## Certificate Lifecycle

- `POST /api/vpn/v1/certificate`
  - Initial persistent registration uses `ClientPublicKey` in raw base64 form, `Mode: "persistent"`, `DeviceName`, and `Features`.
  - The captured persistent feature shape includes `Bouncing: "0"`, `PortForwarding: false`, `SplitTCP: true`, `peerName`, `peerIp`, `peerPublicKey`, and `platform: "Android"`.
  - Renewal requests use `Renew: true` and PEM-wrap the X25519 client public key.

- `GET /api/vpn/v1/certificate/all?Mode=persistent&Offset=0&Limit=51`
  - Inspection path for persistent certificate profiles.

- Certificate responses may expose `Certificate`, `ProfileID` or `SerialNumber`, `ExpirationTime` or `ExpirationTimeMs`, `RefreshTime` or `RefreshTimeMs`, `AssignedIP`, `Endpoint`, `ClientPublicKey`, and `PeerPublicKey`.

## Design Note

- The browser capture shows `Persistent: 0` on the auth/cookies request. PSO should keep that value unless a later capture proves the browser changed behavior.
- Changing the cookie-body `Persistent` default to `1` would diverge from the observed wire shape.

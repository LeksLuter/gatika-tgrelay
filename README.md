# Gatika Telegram Relay

Telegram WebSocket-to-TCP relay with two runtimes:

- **Cloudflare Worker** — current production endpoint, `src/index.mjs`.
- **Netlify Server / Render** — Node.js backup/test endpoint,
  `netlify/server/index.mjs` or `scripts/serve-node-relay.mjs`.

Both accept WebSocket connections from a special client and forward raw
bytes over TCP **only** to Telegram server IP addresses. Everything else is
rejected before any socket is opened.

- Transport: WebSocket in, TCP out (`cloudflare:sockets` on Workers,
  `node:net` on Netlify Server).
- Allowlist: literal dotted-quad IPv4 addresses inside `TELEGRAM_NETS` only.
- Diagnostics: `probe=1` checks TCP connectability, `probe=2` runs one
  MTProto obfuscation handshake (`req_pq_multi`) and returns a hex dump.
- Offline-testable: Worker logic lives in `src/relay.mjs` behind injected
  `connect` / `makeWebSocketPair` factories; Netlify logic lives in
  `src/node-relay.mjs` behind an injected `connect` factory. Only
  `src/index.mjs` imports `cloudflare:sockets`.

No secrets, tokens, or account identifiers are stored in this repository.

## Allowed Telegram networks

Defined in `src/telegram-nets.mjs` (`TELEGRAM_NETS`):

| Base | Prefix | Range |
| --- | --- | --- |
| `91.108.4.0` | `/22` | `91.108.4.0` – `91.108.7.255` |
| `91.108.8.0` | `/22` | `91.108.8.0` – `91.108.11.255` |
| `91.108.12.0` | `/22` | `91.108.12.0` – `91.108.15.255` |
| `91.108.16.0` | `/22` | `91.108.16.0` – `91.108.19.255` |
| `91.108.20.0` | `/22` | `91.108.20.0` – `91.108.23.255` |
| `91.108.56.0` | `/22` | `91.108.56.0` – `91.108.59.255` |
| `91.105.192.0` | `/23` | `91.105.192.0` – `91.105.193.255` |
| `149.154.160.0` | `/20` | `149.154.160.0` – `149.154.175.255` |
| `185.76.151.0` | `/24` | `185.76.151.0` – `185.76.151.255` |

Membership is inclusive of the base address and exclusive of
`base + 2 ** (32 - prefix)`. Hostnames, IPv6 literals, and malformed
IPv4 strings are never allowed.

## Query parameters

All parameters are query-string values on the Worker URL:

### `dst=host[:port]`

- Required for every mode.
- `host` must be a non-empty literal IPv4 address without whitespace or
  extra colons. DNS is never resolved.
- `port` is optional and defaults to `443`.
- When present, `port` must be a decimal integer in `[1, 65535]`.
  `0`, `70000`, empty, signed, or non-numeric ports are rejected.
- The parsed host must satisfy `isAllowedHost(host)`; otherwise the
  request fails with `403` before `connect` is called.

Examples: `dst=91.108.4.5`, `dst=91.108.4.5:443`, `dst=149.154.167.51:443`.

### `dc=<int>`

- Data-center number used only by `probe=2`.
- Defaults to `2` when absent (`?dst=…&probe=2` behaves as `dc=2`).
- Passed to `buildHandshake(random64, dcNum, nonce)` and stored
  little-endian in handshake bytes 60/61.

### `probe=<0|1|2>`

- Absent or `0`: normal relay mode. Requires `Upgrade: websocket`.
- `1`: TCP connectivity diagnostic over plain HTTPS (no upgrade needed).
- `2`: MTProto handshake diagnostic over plain HTTPS (no upgrade needed).
- Any other non-zero numeric value with a WebSocket upgrade falls through
  to relay mode; without an upgrade it is treated as a probe request and
  therefore bypasses the `426` guard.

## Request handling and status codes

| Request | Response |
| --- | --- |
| No `Upgrade: websocket` header and no truthy `probe` | `426` `Gatika relay: только WebSocket`. No socket is opened. |
| `dst` missing, malformed, bad port, or outside Telegram nets | `403` `Gatika relay: адрес не из Telegram`. `connect` is never called. |
| `connect()` throws or returns an unusable socket | `502` `Gatika relay: connect failed`. |
| `?dst=<allowed>&probe=1`, TCP opens | `200` `connected <dst>` (echoes the raw `dst` value). |
| `?dst=<allowed>&probe=1`, TCP fails | `502` `connect failed: <message>`. |
| `?dst=<allowed>&probe=2[&dc=N]` | Always `200` with a diagnostic string (see below). Never throws. |
| `Upgrade: websocket` + allowed `dst` | `101` with the Worker WebSocket attached. Bytes are piped both ways. |

### `probe=2` response format

On success:

```text
resp <n>B plain: <hex>
key: <hex>
iv: <hex>
cipher: <hex>
```

- `<n>` is the received byte length.
- `plain` is the first 40 decrypted bytes (byte-reversed key/IV CTR stream).
- `key`, `iv`, and `cipher` are full lowercase hex dumps.

Failure modes return a single diagnostic line instead:

- `connect failed: …`
- `handshake failed: …`
- `write failed: …`
- `read failed: …`
- `read done, 0 bytes`

The read waits for one chunk with an 8-second timeout implemented via
`reader.cancel()`.

## Example calls

Replace `relay.example` with the deployed Worker hostname.

Check that plain HTTP without upgrade is rejected:

```sh
curl -i 'https://relay.example/?dst=91.108.4.5:443'
# -> 426 Gatika relay: только WebSocket
```

Reject a non-Telegram address (no connection is opened):

```sh
curl -i 'https://relay.example/?dst=8.8.8.8:443' -H 'Upgrade: websocket'
# -> 403 Gatika relay: адрес не из Telegram
```

TCP diagnostic (no WebSocket upgrade required):

```sh
curl -i 'https://relay.example/?dst=91.108.4.5:443&probe=1'
# -> 200 connected 91.108.4.5:443
```

MTProto diagnostic for DC 2:

```sh
curl -i 'https://relay.example/?dst=91.108.4.5:443&probe=2&dc=2'
# -> 200 resp 16B plain: …
```

Relay mode (client must speak WebSocket; raw TCP bytes are tunnelled):

```js
const ws = new WebSocket("wss://relay.example/?dst=149.154.167.51:443");
ws.binaryType = "arraybuffer";
ws.onopen = () => ws.send(new Uint8Array([1, 2, 3]));
ws.onmessage = (ev) => console.log(new Uint8Array(ev.data));
```

## Limits

- **WebSocket only for relaying.** Plain HTTP(S) is accepted solely for
  `probe=1` / `probe=2` diagnostics.
- **IP addresses only.** `dst` never triggers DNS; `example.com:443` is a
  `403`, even if it would resolve to a Telegram range.
- **Telegram ranges only.** Any address outside `TELEGRAM_NETS` is a `403`
  before `connect`.
- **No authentication built in.** Anyone who knows the Worker URL and an
  allowed IP can relay traffic and consume Workers / socket quota.
  Put access control (token, allowlisted client, rate limit) in front if
  the endpoint is public.
- **`probe=2` discloses handshake material.** Its `200` response echoes the
  derived `key`, `iv`, and ciphertext. Gate or disable it before
  production use.
- **Hardcoded ranges drift.** Telegram may change its networks; update
  `src/telegram-nets.mjs` and redeploy when `403`s no longer match reality.
- **Worker backpressure is limited.** Client-to-socket writes are
  serialized through a promise chain (write failure closes with `1011`);
  socket-to-client uses `server.send(value)` without a drain check. The
  Netlify/Node runtime pauses and resumes both sides on `drain`.
- **Netlify Server has platform cuts.** Free WebSockets are closed at
  30 minutes and outbound TCP connections close after 60 seconds without
  traffic. The Node relay sends a `1012` close at 29 minutes so clients
  reconnect before the platform cutoff.

## Tests

Requires Node.js 20 or newer for the test suite. Netlify Server itself
requires Node.js 24; `netlify.toml` sets `NODE_VERSION=24`. No network
access is used; sockets and `WebSocketPair` are faked in tests.

```sh
npm test
# equivalent: node --test
```

Syntax / config check without running tests:

```sh
npm run check
# equivalent per-file node --check over src/*.mjs and test/*.test.mjs
```

What is covered:

- `test/telegram-nets.test.mjs`: range boundaries, invalid IPv4 forms,
  hostname rejection, `parseDst` default port `443`, ports `0`/`70000`.
- `test/mtproto-crypto.test.mjs`: output lengths, determinism, differing
  keystreams for differing IVs/keys, `xorBuf` round-trip, input immutability.
- `test/relay.test.mjs`: `426` without upgrade, `403` without calling
  `connect`, `probe=1` success/failure, `probe=2` against a simulated
  socket, `101` upgrade with one frame forwarded in each direction.
- `test/node-relay.test.mjs`: masked-frame parser and fragmentation,
  unmasked-frame rejection, `/health`, `403`/`426` guards, `probe=1`
  through an injected transport, and a real local `http.Server` WebSocket
  upgrade with bytes echoed through `node:net`.

`src/index.mjs` is syntax-checked only because `cloudflare:sockets` and
the `WebSocketPair` global do not exist under Node.

## Deployment (Cloudflare Workers)

`wrangler.toml` contains only routing metadata (no secrets):

```toml
name = "gatika-tgrelay"
main = "src/index.mjs"
compatibility_date = "2024-11-01"
workers_dev = true
```

Steps:

1. Install the toolchain: Node.js 20+ and `wrangler` (`npm i -g wrangler`
   or `npx wrangler --version`).
2. Authenticate locally (`wrangler login`); never commit tokens or
   account IDs to this repository.
3. Verify offline: `npm run check && npm test`.
4. Deploy: `npx wrangler deploy` (or `wrangler deploy`).
5. Smoke-test the deployment from a machine with internet access:
   - `curl 'https://<worker.dev>/?dst=91.108.4.5:443&probe=1'`
     expects `200 connected …`.
   - `curl 'https://<worker.dev>/?dst=91.108.4.5:443&probe=2&dc=2'`
     expects `200 resp …` or a `read …` diagnostic line.
   - Open a WebSocket to `wss://<worker.dev>/?dst=<allowed-ip>:443`
     from the special client and confirm bidirectional traffic.
6. For production, gate or remove `probe=2` and add an access-control
   layer in front of the Worker.

The current live endpoint is
`https://gatika-tgrelay.goldklonleks.workers.dev/` (Worker `gatika-tgrelay`).
The GitHub Actions workflow `.github/workflows/deploy.yml` runs the tests on
every push and deploys to Cloudflare only when `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` are configured as repository secrets. Without those
secrets the deploy job is skipped and the test job still runs.

## Deployment (Netlify Server)

> **Plan gate:** Netlify Server requires a **credit-based** Netlify plan.
> Legacy Free/Starter/Pro teams get `422 Netlify Server is only available on
> credit-based plans` during the build, even though Netlify Server itself is
> free during Early Access. Switching from a legacy plan is irreversible.
> If you do not want to switch, use the Render blueprint below instead.

This is an optional backup/test runtime, not a replacement for the working
Cloudflare Worker. It uses Netlify Server, a long-running Node.js process —
not Netlify Functions or Edge Functions, which cannot hold an incoming
WebSocket.

Files:

- `netlify/server/index.mjs` — default-exports the `http.Server` from
  `src/node-relay.mjs`; Netlify starts it and routes upgrades to it.
- `netlify.toml` — publishes `public/`, sets `NODE_VERSION=24`, region `fra`.
- `public/index.html` — small status page at `/`.
- `scripts/serve-node-relay.mjs` — local runner for the same server.

Steps:

1. Push this repository to GitHub (the Worker files remain unchanged).
2. In Netlify, create a new project from the repository. Netlify Server is
   an Early Access feature; enable it for the team if it is not visible.
3. Keep the default build command empty; Netlify reads `netlify.toml`.
   The server entry must stay at `netlify/server/index.mjs`.
4. Deploy, then smoke-test:
   - `https://<site>.netlify.app/health` -> `ok`.
   - `https://<site>.netlify.app/apiws?dst=91.108.4.5:443&probe=1` ->
     `connected 91.108.4.5:443`.
   - `wss://<site>.netlify.app/apiws?dst=<allowed-ip>:443&dc=2` from the
     special client.
5. Run a real client for at least 35 minutes. The relay closes at 29
   minutes with WebSocket code `1012`; verify that the client reconnects
   without user action.

Local run:

```sh
npm run check && npm test
node scripts/serve-node-relay.mjs
# another terminal:
curl 'http://127.0.0.1:8787/health'
curl 'http://127.0.0.1:8787/apiws?dst=91.108.4.5:443&probe=1'
```

Netlify Server limits that matter:

- Free/Personal: one small instance (1 GB RAM, shared vCPU).
- WebSocket connection: closed after 30 minutes on Free, 2 hours on paid.
- Outbound TCP: closed after 60 seconds without data in either direction;
  TCP keepalive does not count.
- Instance lifetime: at most 8 hours; a replacement closes connections.
- Server is free during Early Access; after GA, compute consumes credits.

Because of the 30-minute cut and 60-second idle rule, treat Netlify as a
test/secondary endpoint. Keep Cloudflare as the primary relay until a real
Telegram client proves reconnects are acceptable.

## Deployment (Render, free)

Render is the simplest free alternative when Netlify Server is blocked by
the plan gate. It runs the same plain Node relay as a normal web service,
supports inbound WebSockets, and allows outbound TCP to Telegram.

`render.yaml` in the repository root is a Render Blueprint:

- runtime: Node.js 24;
- plan: Free;
- region: Frankfurt;
- start: `node scripts/serve-node-relay.mjs`;
- health check: `/health`;
- `WS_LIFETIME_MS=0` disables the 29-minute Netlify close, because Render
  does not impose a maximum WebSocket duration.

Steps:

1. In Render: **New → Blueprint**, connect `LeksLuter/gatika-tgrelay`,
   apply the blueprint.
2. Wait for the first deploy, then check:
   - `https://<service>.onrender.com/health` -> `ok`;
   - `https://<service>.onrender.com/apiws?dst=91.108.4.5:443&probe=1` ->
     `connected 91.108.4.5:443`.
3. Client endpoint:
   `wss://<service>.onrender.com/apiws?dst=<telegram-ip>:443&dc=2`.
4. Run a real client. Render does not cut WebSockets by time, but a Free
   service spins down after 15 minutes without inbound HTTP or WebSocket
   traffic, then takes about a minute to wake up. Telegram traffic normally
   prevents that; idle reconnects must tolerate the cold start.

Render Free limits that matter: 750 instance hours per workspace per month,
one service, 512 MB RAM, and outbound bandwidth counting against the free
allowance. Netlify remains an option only after switching to a credit-based
plan.

### LXI free hosting is not a relay runtime

LXI Free provides PHP/Apache web hosting and scheduled tasks, not a
long-running process that can hold a WebSocket Upgrade and an outbound TCP
socket. The LXI Pro “persistent Python worker” is sold for bots and
background tasks; a public WebSocket port is not part of that description.
Do not publish this Worker to LXI expecting `/apiws` to work: LXI Maker's
`plesk` publication needs a verified build, and the generated artifact is a
Cloudflare Worker, not a PHP script. Use Cloudflare Workers, a foreign VPS,
 or a WebSocket-capable PaaS for the relay itself.

## Project layout

```text
src/index.mjs            Worker entrypoint (only cloudflare:sockets import)
src/relay.mjs            Worker request tree + byte piping (createRelay, msgBytes)
src/node-relay.mjs       Node http.Server + WebSocket framing + net relay
src/telegram-nets.mjs    TELEGRAM_NETS, ipToInt, isAllowedHost, parseDst
src/mtproto-crypto.mjs   ecbBlock, ctrStream, xorBuf, buildHandshake
src/mtproto-probe.mjs    mtprotoProbe socket I/O + response decryption
netlify/server/index.mjs Netlify Server entry (exports http.Server)
netlify.toml             Node 24, public/, Frankfurt region
render.yaml              Render Free blueprint (Node 24, Frankfurt)
public/index.html        Status page served by Netlify at /
scripts/serve-node-relay.mjs  Local Netlify Server runner
test/                    Offline node:test suites (fake sockets/pairs)
wrangler.toml            Worker name, entrypoint, compatibility date
package.json             Private ESM package, test/check scripts
```

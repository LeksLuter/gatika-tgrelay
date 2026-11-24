/**
 * Cloudflare Worker entrypoint for the Telegram WebSocket relay.
 *
 * This is the only module allowed to import `cloudflare:sockets`.
 * All request logic lives in `relay.mjs` behind `createRelay` and is
 * exercised offline with injected fakes; this file only binds the real
 * platform factories (`connect` and the `WebSocketPair` global) and
 * exposes the default `fetch` handler.
 */

import { connect } from "cloudflare:sockets";
import { createRelay } from "./relay.mjs";

const relay = createRelay({
  connect,
  makeWebSocketPair: () => new WebSocketPair()
});

/**
 * Worker default export.
 * @type {{ fetch: (request: Request, env?: unknown, ctx?: unknown) => Promise<Response> }}
 */
const worker = {
  fetch(request) {
    return relay.fetch(request);
  }
};

export default worker;

/**
 * WebSocket relay handler (dependency-injected, platform-free).
 *
 * Receives `connect` and `makeWebSocketPair` factories via `createRelay`
 * so all logic stays testable offline under `node --test`.
 * Only `src/index.mjs` may import `cloudflare:sockets`.
 */

import { parseDst, isAllowedHost } from "./telegram-nets.mjs";
import { mtprotoProbe } from "./mtproto-probe.mjs";

const MSG_426 = "Gatika relay: \u0442\u043E\u043B\u044C\u043A\u043E WebSocket";
const MSG_403 = "Gatika relay: \u0430\u0434\u0440\u0435\u0441 \u043D\u0435 \u0438\u0437 Telegram";
const MSG_502_CONNECT = "Gatika relay: connect failed";

/**
 * Normalise a WebSocket `message` event payload to bytes.
 *
 * @param {{ data?: unknown }} event - Message event.
 * @returns {Promise<Uint8Array>} Byte view of the payload.
 */
export async function msgBytes(event) {
  const d = event ? event.data : undefined;
  if (typeof d === "string") return new TextEncoder().encode(d);
  if (d instanceof Uint8Array) return d.slice();
  if (d instanceof ArrayBuffer) return new Uint8Array(d.slice(0));
  if (typeof SharedArrayBuffer !== "undefined" && d instanceof SharedArrayBuffer) {
    return new Uint8Array(d);
  }
  if (ArrayBuffer.isView(d)) {
    return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  }
  if (d && typeof d.arrayBuffer === "function") {
    try {
      const ab = await d.arrayBuffer();
      if (ab instanceof ArrayBuffer) return new Uint8Array(ab);
      if (ab instanceof Uint8Array) return ab.slice();
      if (ArrayBuffer.isView(ab)) {
        return new Uint8Array(ab.buffer, ab.byteOffset, ab.byteLength);
      }
    } catch {
      return new Uint8Array(0);
    }
  }
  return new Uint8Array(0);
}

function errMessage(err) {
  if (err instanceof Error && typeof err.message === "string") return err.message;
  if (typeof err === "string") return err;
  try {
    const s = String(err);
    return s === "" ? "unknown error" : s;
  } catch {
    return "unknown error";
  }
}

function pairSides(pair) {
  if (Array.isArray(pair)) return [pair[0], pair[1]];
  const values = Object.values(pair);
  return [values[0], values[1]];
}

function closeServer(server, code, reason) {
  try {
    if (server && typeof server.close === "function") server.close(code, reason);
  } catch {
    // Best effort only.
  }
}

function closeSocket(socket) {
  try {
    if (socket && typeof socket.close === "function") socket.close();
  } catch {
    // Best effort only.
  }
}

/**
 * Create a relay handler with injected platform factories.
 *
 * @param {{ connect: (opts: { hostname: string, port: number }) => any, makeWebSocketPair: () => any }} deps
 * @returns {{ fetch: (request: Request) => Promise<Response> }}
 */
export function createRelay(deps) {
  const connect = deps ? deps.connect : undefined;
  const makeWebSocketPair = deps ? deps.makeWebSocketPair : undefined;
  if (typeof connect !== "function") {
    throw new TypeError("createRelay requires a connect function");
  }
  if (typeof makeWebSocketPair !== "function") {
    throw new TypeError("createRelay requires a makeWebSocketPair function");
  }

  async function fetch(request) {
    const url = new URL(request.url);
    const probe = Number(url.searchParams.get("probe") || 0);

    const upgrade = request.headers.get("Upgrade");
    if (upgrade !== "websocket" && !probe) {
      return new Response(MSG_426, { status: 426 });
    }

    const dstRaw = url.searchParams.get("dst") || "";
    const parsed = parseDst(dstRaw);
    if (parsed === null || !isAllowedHost(parsed.host)) {
      return new Response(MSG_403, { status: 403 });
    }
    const { host, port } = parsed;
    const dcNum = Number(url.searchParams.get("dc") || "2");

    let socket;
    try {
      socket = connect({ hostname: host, port });
    } catch {
      return new Response(MSG_502_CONNECT, { status: 502 });
    }
    if (!socket || typeof socket !== "object") {
      return new Response(MSG_502_CONNECT, { status: 502 });
    }

    if (probe === 1) {
      try {
        await socket.opened;
        return new Response("connected " + dstRaw, { status: 200 });
      } catch (e) {
        return new Response("connect failed: " + errMessage(e), { status: 502 });
      }
    }

    if (probe === 2) {
      let text;
      try {
        text = await mtprotoProbe(socket, dcNum);
      } catch (e) {
        text = "read failed: " + errMessage(e);
      }
      return new Response(String(text), { status: 200 });
    }

    // Unknown non-zero probe values fall through to the relay path only
    // when the caller performed a WebSocket upgrade; otherwise the 426
    // guard above has already rejected the request. NaN probe with an
    // upgrade also reaches here, which matches the reference behaviour.

    let client;
    let server;
    try {
      const pair = makeWebSocketPair();
      [client, server] = pairSides(pair);
    } catch {
      closeSocket(socket);
      return new Response(MSG_502_CONNECT, { status: 502 });
    }
    if (!client || !server) {
      closeSocket(socket);
      return new Response(MSG_502_CONNECT, { status: 502 });
    }

    try {
      if (typeof server.accept === "function") server.accept();
    } catch {
      // accept() best effort.
    }

    let writer = null;
    try {
      writer = socket.writable.getWriter();
    } catch {
      closeServer(server, 1011, "write failed");
      closeSocket(socket);
      return new Response(MSG_502_CONNECT, { status: 502 });
    }

    const opened = socket.opened && typeof socket.opened.then === "function"
      ? socket.opened.then(() => undefined)
      : Promise.resolve();
    let chain = opened;

    const onMessage = (event) => {
      chain = chain
        .then(() => msgBytes(event))
        .then((data) => writer.write(data))
        .catch(() => closeServer(server, 1011, "write failed"));
    };
    try {
      if (typeof server.addEventListener === "function") {
        server.addEventListener("message", onMessage);
      } else if (typeof server.onmessage !== "undefined") {
        const prev = server.onmessage;
        server.onmessage = (ev) => {
          if (typeof prev === "function") {
            try { prev(ev); } catch { /* ignore */ }
          }
          onMessage(ev);
        };
      }
    } catch {
      // Listener registration best effort.
    }

    (async () => {
      let reader = null;
      try {
        reader = socket.readable.getReader();
      } catch {
        closeServer(server, 1000, "closed");
        closeSocket(socket);
        return;
      }
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength) {
            try {
              server.send(value);
            } catch {
              break;
            }
          }
        }
      } catch {
        // Read errors simply terminate the relay loop.
      } finally {
        try {
          if (reader && typeof reader.releaseLock === "function") reader.releaseLock();
        } catch { /* ignore */ }
        try {
          if (writer && typeof writer.releaseLock === "function") writer.releaseLock();
        } catch { /* ignore */ }
        closeServer(server, 1000, "closed");
        closeSocket(socket);
      }
    })();

    let res = new Response(null, { status: 200 });
    try {
      Object.defineProperty(res, "status", { value: 101, configurable: true });
    } catch { /* ignore */ }
    try {
      res.webSocket = client;
    } catch { /* ignore */ }
    // Under Node the `webSocket` init key is ignored; expose it so
    // offline tests (and any non-Worker runtime) can observe the peer.
    try {
      if (!res.webSocket) res.webSocket = client;
    } catch { /* ignore */ }
    return res;
  }

  return { fetch };
}

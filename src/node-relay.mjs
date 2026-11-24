/**
 * Netlify Server / plain Node.js WebSocket relay for Telegram.
 *
 * This runtime owns a real http.Server and a real net.Socket, so it replaces
 * Cloudflare's connect()/WebSocketPair with Node primitives. The public wire
 * contract is unchanged:
 *
 *   wss://<host>/apiws?dst=<telegram-ip>:443&dc=<n>
 *
 * Telegram MTProto stays end-to-end encrypted; this process only forwards
 * opaque bytes and never sees Telegram credentials or message plaintext.
 *
 * The module is dependency-injected for offline tests: createRelayServer()
 * accepts a connect() factory and an optional WebSocket lifetime.
 */

import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";

import { parseDst, isAllowedHost } from "./telegram-nets.mjs";
import { mtprotoProbe } from "./mtproto-probe.mjs";

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
// MTProto upload chunks are normally 512 KiB; 8 MiB leaves room for
// larger control frames without letting one client exhaust instance memory.
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_WS_LIFETIME_MS = 29 * 60 * 1000;
const RELAY_PATH = "/apiws";
const HEALTH_PATH = "/health";

const MSG_426 = "Gatika relay: \u0442\u043E\u043B\u044C\u043A\u043E WebSocket";
const MSG_403 = "Gatika relay: \u0430\u0434\u0440\u0435\u0441 \u043D\u0435 \u0438\u0437 Telegram";
const MSG_502 = "Gatika relay: connect failed";

/**
 * Build one unmasked WebSocket frame. Server-to-client frames are never masked.
 *
 * @param {Uint8Array|Buffer|string} payload
 * @param {number} [opcode=0x2]
 * @returns {Buffer}
 */
export function encodeFrame(payload, opcode = 0x2) {
  const body = Buffer.isBuffer(payload)
    ? payload
    : typeof payload === "string"
      ? Buffer.from(payload)
      : Buffer.from(payload);
  const length = body.length;
  let header;
  if (length < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = length;
  } else if (length < 65536) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = 0x80 | (opcode & 0x0f);
  return Buffer.concat([header, body]);
}

/**
 * Build a close frame with a status code and an optional reason.
 *
 * @param {number} [code=1000]
 * @param {string} [reason=""]
 * @returns {Buffer}
 */
export function encodeClose(code = 1000, reason = "") {
  const text = Buffer.from(String(reason)).subarray(0, 123);
  const payload = Buffer.allocUnsafe(2 + text.length);
  payload.writeUInt16BE(code & 0xffff, 0);
  text.copy(payload, 2);
  return encodeFrame(payload, 0x8);
}

/**
 * Try to take one complete frame from the front of a buffer.
 *
 * @param {Buffer} buffer
 * @returns {{ fin: boolean, opcode: number, payload: Buffer, rest: Buffer }|{ error: number, reason: string, rest: Buffer }|null}
 */
function takeFrame(buffer) {
  if (buffer.length < 2) return null;
  const b0 = buffer[0];
  const b1 = buffer[1];
  const fin = (b0 & 0x80) !== 0;
  const rsv = b0 & 0x70;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  const length7 = b1 & 0x7f;

  if (rsv !== 0) {
    return { error: 1002, reason: "reserved bits set", rest: buffer.subarray(2) };
  }
  if (!masked) {
    return { error: 1002, reason: "client frame is not masked", rest: buffer.subarray(2) };
  }
  if (opcode >= 0x8 && (length7 > 125 || !fin)) {
    return { error: 1002, reason: "invalid control frame", rest: buffer.subarray(2) };
  }

  let offset = 2;
  let length = length7;
  if (length7 === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length7 === 127) {
    if (buffer.length < 10) return null;
    const big = buffer.readBigUInt64BE(2);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      return { error: 1009, reason: "frame too large", rest: buffer.subarray(10) };
    }
    length = Number(big);
    offset = 10;
  }
  if (length > MAX_PAYLOAD_BYTES) {
    return { error: 1009, reason: "frame too large", rest: buffer.subarray(offset) };
  }
  if (buffer.length < offset + 4 + length) return null;

  const mask = buffer.subarray(offset, offset + 4);
  offset += 4;
  const source = buffer.subarray(offset, offset + length);
  const payload = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i++) payload[i] = source[i] ^ mask[i & 3];

  return { fin, opcode, payload, rest: buffer.subarray(offset + length) };
}

/**
 * Incremental client-to-server frame parser (client frames must be masked).
 *
 * @param {{ onMessage: (payload: Buffer, opcode: number) => void, onControl: (event: { type: string, code?: number, reason?: string, payload?: Buffer }) => void, onError: (code: number, reason: string) => void, maxPayload?: number }} handlers
 * @returns {{ push: (chunk: Buffer|Uint8Array) => void }}
 */
export function createFrameParser(handlers) {
  let buffer = Buffer.alloc(0);
  let fragments = [];
  let fragmentOpcode = 0;
  let failed = false;
  const maxPayload = handlers.maxPayload || MAX_PAYLOAD_BYTES;

  function fail(code, reason) {
    if (failed) return;
    failed = true;
    handlers.onError(code, reason);
  }

  function dispatch(payload, opcode) {
    if (payload.length > maxPayload) {
      fail(1009, "message too large");
      return;
    }
    handlers.onMessage(payload, opcode);
  }

  function push(chunk) {
    if (failed) return;
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    for (;;) {
      const frame = takeFrame(buffer);
      if (frame === null) return;
      buffer = frame.rest;
      if (frame.error) {
        fail(frame.error, frame.reason);
        return;
      }

      const { fin, opcode, payload } = frame;
      if (opcode === 0x8) {
        if (!fin || payload.length > 125) {
          fail(1002, "invalid close frame");
          return;
        }
        const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
        const reason = payload.length > 2 ? payload.subarray(2).toString("utf8") : "";
        handlers.onControl({ type: "close", code, reason });
        return;
      }
      if (opcode === 0x9) {
        if (!fin || payload.length > 125) {
          fail(1002, "invalid ping frame");
          return;
        }
        handlers.onControl({ type: "ping", payload });
        continue;
      }
      if (opcode === 0xa) {
        if (!fin || payload.length > 125) {
          fail(1002, "invalid pong frame");
          return;
        }
        continue;
      }
      if (opcode === 0x0) {
        if (fragments.length === 0 || fragmentOpcode === 0) {
          fail(1002, "unexpected continuation frame");
          return;
        }
        fragments.push(payload);
        const total = fragments.reduce((n, item) => n + item.length, 0);
        if (total > maxPayload) {
          fail(1009, "message too large");
          return;
        }
        if (fin) {
          const combined = Buffer.concat(fragments);
          fragments = [];
          const kind = fragmentOpcode;
          fragmentOpcode = 0;
          dispatch(combined, kind);
        }
        continue;
      }
      if (opcode !== 0x1 && opcode !== 0x2) {
        fail(1002, "unsupported opcode");
        return;
      }
      if (!fin) {
        if (fragments.length !== 0) {
          fail(1002, "nested fragmented message");
          return;
        }
        fragments = [payload];
        fragmentOpcode = opcode;
        continue;
      }
      dispatch(payload, opcode);
    }
  }

  return { push };
}

function sendHttp(res, status, body, extraHeaders = {}) {
  const text = String(body);
  const headers = {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(text),
    "Cache-Control": "no-store",
    ...extraHeaders,
  };
  res.writeHead(status, headers);
  res.end(text);
}

function rejectUpgrade(socket, status, body, onFlushed) {
  if (!socket || socket.destroyed) {
    if (typeof onFlushed === "function") onFlushed();
    return;
  }
  const text = String(body);
  const response =
    "HTTP/1.1 " + status + " " + (http.STATUS_CODES[status] || "Error") + "\r\n" +
    "Connection: close\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "Content-Length: " + Buffer.byteLength(text) + "\r\n" +
    "\r\n" +
    text;
  try {
    socket.end(response, () => {
      if (typeof onFlushed === "function") onFlushed();
    });
  } catch {
    if (typeof onFlushed === "function") onFlushed();
  }
}

function socketAddress(dstRaw, parsed) {
  return dstRaw || (parsed ? parsed.host + ":" + parsed.port : "");
}

function connectTarget(connect, parsed) {
  try {
    return connect({ host: parsed.host, port: parsed.port });
  } catch {
    return null;
  }
}

function probeTcp(connect, parsed, dstRaw, res) {
  const target = connectTarget(connect, parsed);
  if (!target) {
    sendHttp(res, 502, MSG_502);
    return;
  }
  let done = false;
  const finish = (status, text) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    try { target.destroy(); } catch { /* ignore */ }
    sendHttp(res, status, text);
  };
  const timer = setTimeout(() => finish(502, "connect failed: timeout"), CONNECT_TIMEOUT_MS);
  target.once("connect", () => finish(200, "connected " + socketAddress(dstRaw, parsed)));
  target.once("error", () => finish(502, MSG_502));
}

/**
 * Minimal Cloudflare-like socket facade for mtprotoProbe().
 * It intentionally supports only the read/write operations the probe needs.
 */
function wrapNodeSocket(socket) {
  let openedResolve;
  let openedReject;
  const opened = new Promise((resolve, reject) => {
    openedResolve = resolve;
    openedReject = reject;
  });
  socket.once("connect", () => openedResolve());
  socket.once("error", (err) => openedReject(err));
  socket.pause();

  let pendingRead = null;
  let queue = [];
  let ended = false;
  let listenerAttached = false;

  function settleRead() {
    if (!pendingRead) return;
    const resolve = pendingRead;
    pendingRead = null;
    const value = queue.shift();
    if (value) resolve({ value, done: false });
    else resolve({ value: undefined, done: true });
  }

  function onData(chunk) {
    queue.push(Buffer.from(chunk));
    settleRead();
  }
  function onEnd() {
    ended = true;
    settleRead();
  }
  function onError() {
    ended = true;
    settleRead();
  }

  const readable = {
    getReader() {
      if (!listenerAttached) {
        listenerAttached = true;
        socket.on("data", onData);
        socket.once("end", onEnd);
        socket.once("close", onEnd);
        socket.once("error", onError);
      }
      return {
        read() {
          if (queue.length > 0) {
            return Promise.resolve({ value: queue.shift(), done: false });
          }
          if (ended) return Promise.resolve({ value: undefined, done: true });
          socket.resume();
          return new Promise((resolve) => { pendingRead = resolve; });
        },
        cancel() {
          ended = true;
          try { socket.destroy(); } catch { /* ignore */ }
          settleRead();
          return Promise.resolve();
        },
        releaseLock() {
          socket.pause();
        },
      };
    },
  };

  const writable = {
    getWriter() {
      return {
        write(chunk) {
          return new Promise((resolve, reject) => {
            if (socket.destroyed) {
              reject(new Error("socket closed"));
              return;
            }
            socket.write(Buffer.from(chunk), (err) => (err ? reject(err) : resolve(undefined)));
          });
        },
        releaseLock() {},
      };
    },
  };

  return { opened, readable, writable, close: () => socket.destroy() };
}

async function probeMtproto(connect, parsed, dcNum, res) {
  const target = connectTarget(connect, parsed);
  if (!target) {
    sendHttp(res, 502, MSG_502);
    return;
  }
  try {
    const text = await mtprotoProbe(wrapNodeSocket(target), dcNum);
    sendHttp(res, 200, text);
  } finally {
    try { target.destroy(); } catch { /* ignore */ }
  }
}

function handleHttp(connect, req, res) {
  let url;
  try {
    url = new URL(req.url || "/", "http://localhost");
  } catch {
    sendHttp(res, 400, "bad request");
    return;
  }

  if (url.pathname === HEALTH_PATH) {
    sendHttp(res, 200, "ok");
    return;
  }
  if (url.pathname === RELAY_PATH) {
    const probe = Number(url.searchParams.get("probe") || 0);
    const dstRaw = url.searchParams.get("dst") || "";
    const parsed = parseDst(dstRaw);
    if (parsed === null || !isAllowedHost(parsed.host)) {
      sendHttp(res, 403, MSG_403);
      return;
    }
    if (probe === 1) {
      probeTcp(connect, parsed, dstRaw, res);
      return;
    }
    if (probe === 2) {
      const dcNum = Number(url.searchParams.get("dc") || "2");
      void probeMtproto(connect, parsed, dcNum, res).catch(() => {
        if (!res.headersSent) sendHttp(res, 500, "probe failed");
        else res.destroy();
      });
      return;
    }
    sendHttp(res, 426, MSG_426);
    return;
  }
  if (url.pathname === "/") {
    sendHttp(res, 200, "Gatika Telegram relay. Use /apiws?dst=<telegram-ip>:443");
    return;
  }
  sendHttp(res, 404, "not found");
}

function handleUpgrade(connect, wsLifetimeMs, req, socket, head) {
  let url;
  try {
    url = new URL(req.url || "/", "http://localhost");
  } catch {
    rejectUpgrade(socket, 400, "bad request");
    return;
  }
  if (url.pathname !== RELAY_PATH) {
    rejectUpgrade(socket, 404, "not found");
    return;
  }

  const dstRaw = url.searchParams.get("dst") || "";
  const parsed = parseDst(dstRaw);
  if (parsed === null || !isAllowedHost(parsed.host)) {
    rejectUpgrade(socket, 403, MSG_403);
    return;
  }

  const key = req.headers["sec-websocket-key"];
  const version = req.headers["sec-websocket-version"];
  if (typeof key !== "string" || Buffer.from(key, "base64").length !== 16 || version !== "13") {
    rejectUpgrade(socket, 400, "invalid websocket handshake");
    return;
  }
  const accept = crypto
    .createHash("sha1")
    .update(key + WS_GUID)
    .digest("base64");

  const target = connectTarget(connect, parsed);
  if (!target) {
    rejectUpgrade(socket, 502, MSG_502);
    return;
  }

  let upgraded = false;
  let finished = false;
  let lifetimeTimer = null;
  let connectTimer = null;

  function clearTimers() {
    if (connectTimer) clearTimeout(connectTimer);
    if (lifetimeTimer) clearTimeout(lifetimeTimer);
    connectTimer = null;
    lifetimeTimer = null;
  }

  function finish() {
    if (finished) return;
    finished = true;
    clearTimers();
    try { target.destroy(); } catch { /* ignore */ }
    try { socket.end(); } catch { /* ignore */ }
    setTimeout(() => {
      try { socket.destroy(); } catch { /* ignore */ }
    }, 100).unref?.();
  }

  function closeWs(code, reason) {
    if (finished) return;
    try {
      socket.write(encodeClose(code, reason));
    } catch {
      /* ignore */
    }
    finish();
  }

  function cleanup() {
    if (finished) return;
    finished = true;
    clearTimers();
    try { target.destroy(); } catch { /* ignore */ }
    try { socket.destroy(); } catch { /* ignore */ }
  }

  socket.once("close", cleanup);
  socket.once("error", cleanup);
  target.once("error", () => {
    if (!upgraded) {
      rejectUpgrade(socket, 502, MSG_502, cleanup);
      return;
    }
    closeWs(1011, "target error");
  });

  connectTimer = setTimeout(() => {
    if (upgraded) return;
    rejectUpgrade(socket, 502, "connect failed: timeout", cleanup);
  }, CONNECT_TIMEOUT_MS);

  target.once("connect", () => {
    if (finished) return;
    if (connectTimer) clearTimeout(connectTimer);
    connectTimer = null;
    upgraded = true;

    target.setNoDelay(true);
    target.setKeepAlive(true, 30_000);
    socket.setNoDelay(true);

    const parser = createFrameParser({
      onMessage(payload) {
        if (finished) return;
        try {
          if (!target.write(payload)) {
            socket.pause();
            target.once("drain", () => {
              if (!finished) socket.resume();
            });
          }
        } catch {
          closeWs(1011, "write failed");
        }
      },
      onControl(event) {
        if (event.type === "ping") {
          try { socket.write(encodeFrame(event.payload, 0xa)); } catch { closeWs(1011, "write failed"); }
          return;
        }
        if (event.type === "close") {
          closeWs(event.code || 1000, event.reason || "");
        }
      },
      onError(code, reason) {
        closeWs(code, reason);
      },
    });

    socket.on("data", (chunk) => {
      if (!finished) parser.push(chunk);
    });

    try {
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Accept: " + accept + "\r\n" +
        "\r\n"
      );
    } catch {
      cleanup();
      return;
    }

    if (head && head.length > 0) parser.push(head);

    target.on("data", (chunk) => {
      if (finished) return;
      try {
        if (!socket.write(encodeFrame(chunk, 0x2))) {
          target.pause();
          socket.once("drain", () => {
            if (!finished) target.resume();
          });
        }
      } catch {
        closeWs(1011, "write failed");
      }
    });
    target.once("end", () => closeWs(1000, "target closed"));
    target.once("close", () => {
      if (!finished) closeWs(1000, "target closed");
    });

    // Netlify closes WebSockets at 30 minutes on Free. Close one minute
    // earlier with 1012 (restart) so clients reconnect deliberately.
    if (wsLifetimeMs > 0) {
      lifetimeTimer = setTimeout(() => closeWs(1012, "reconnect"), wsLifetimeMs);
      lifetimeTimer.unref?.();
    }
  });
}

/**
 * Create the relay's Node http.Server.
 *
 * @param {{ connect?: (opts: { host: string, port: number }) => any, wsLifetimeMs?: number }} [options]
 * @returns {import("node:http").Server}
 */
export function createRelayServer(options = {}) {
  const connect = typeof options.connect === "function"
    ? options.connect
    : (opts) => net.connect(opts);
  // Netlify needs the 29-minute close; hosts without that cap can set
  // WS_LIFETIME_MS=0 (Render blueprint does this) to keep sockets open.
  const configured = Number(options.wsLifetimeMs ?? process.env.WS_LIFETIME_MS);
  const wsLifetimeMs = Number.isFinite(configured) && configured >= 0
    ? configured
    : DEFAULT_WS_LIFETIME_MS;

  const trackedSockets = new Set();
  const server = http.createServer((req, res) => {
    try {
      handleHttp(connect, req, res);
    } catch {
      if (!res.headersSent) sendHttp(res, 500, "internal error");
      else res.destroy();
    }
  });
  server.on("connection", (socket) => {
    trackedSockets.add(socket);
    socket.once("close", () => trackedSockets.delete(socket));
  });
  server.on("upgrade", (req, socket, head) => {
    try {
      handleUpgrade(connect, wsLifetimeMs, req, socket, head);
    } catch {
      rejectUpgrade(socket, 500, "internal error");
    }
  });

  // server.close() alone waits for upgraded sockets that Node no longer
  // tracks as ordinary requests. Tests and local shutdown use this helper
  // to destroy every accepted connection before waiting for close().
  server.closeRelay = () => {
    for (const socket of trackedSockets) {
      try { socket.destroy(); } catch { /* ignore */ }
    }
    return new Promise((resolve) => server.close(() => resolve()));
  };

  return server;
}

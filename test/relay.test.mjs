import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRelay, msgBytes } from "../src/relay.mjs";

const ALLOWED = "91.108.4.5";
const ALLOWED_DST = `${ALLOWED}:443`;

function req(url, { upgrade = false } = {}) {
  const headers = upgrade ? { Upgrade: "websocket" } : {};
  return new Request(url, { headers });
}

function okSocket({ written = null, chunks = [], openedFails = false } = {}) {
  const log = written || [];
  const queue = chunks.map((c) => ({ value: c, done: false }));
  queue.push({ value: undefined, done: true });
  const socket = {
    opened: openedFails ? Promise.reject(new Error("boom")) : Promise.resolve(undefined),
    writable: {
      getWriter() {
        return {
          write(chunk) {
            log.push(chunk);
            return Promise.resolve(undefined);
          },
          releaseLock() {},
        };
      },
    },
    readable: {
      getReader() {
        return {
          read() {
            const next = queue.shift() || { value: undefined, done: true };
            return Promise.resolve(next);
          },
          cancel() {},
          releaseLock() {},
        };
      },
    },
    close() {
      socket.closed = true;
    },
  };
  socket.log = log;
  return socket;
}

function makeFakePairHolder() {
  const listeners = { message: [] };
  const server = {
    accepted: false,
    sent: [],
    closeCode: null,
    closeReason: null,
    accept() {
      server.accepted = true;
    },
    send(data) {
      server.sent.push(data);
    },
    close(code, reason) {
      server.closeCode = code;
      server.closeReason = reason;
    },
    addEventListener(type, fn) {
      if (type === "message") listeners.message.push(fn);
    },
    emitMessage(data) {
      const ev = { data };
      for (const fn of listeners.message) fn(ev);
    },
  };
  const client = { id: "client" };
  const holder = { server, client };
  const factory = () => ({ client, server });
  holder.factory = factory;
  return holder;
}

const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

describe("msgBytes", () => {
  it("encodes strings and passes through bytes", async () => {
    assert.deepEqual([...await msgBytes({ data: "hi" })], [...new TextEncoder().encode("hi")]);
    const buf = new Uint8Array([1, 2, 3]);
    assert.deepEqual([...await msgBytes({ data: buf })], [1, 2, 3]);
    const ab = new Uint8Array([4, 5]).buffer;
    assert.deepEqual([...await msgBytes({ data: ab })], [4, 5]);
    assert.deepEqual([...await msgBytes({ data: null })], []);
  });
});

describe("relay 426 guard", () => {
  it("answers 426 without Upgrade and without probe", async () => {
    let called = false;
    const relay = createRelay({
      connect() { called = true; return okSocket(); },
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED_DST}`));
    assert.equal(res.status, 426);
    assert.equal(called, false);
  });
});

describe("relay 403 guard", () => {
  it("rejects non-Telegram dst without opening a connection", async () => {
    let called = false;
    const relay = createRelay({
      connect() { called = true; return okSocket(); },
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(
      req(`https://relay.example/?dst=8.8.8.8:443`, { upgrade: true }),
    );
    assert.equal(res.status, 403);
    assert.equal(called, false);
  });

  it("rejects missing dst and invalid ports without connecting", async () => {
    let calls = 0;
    const relay = createRelay({
      connect() { calls++; return okSocket(); },
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const r1 = await relay.fetch(req("https://relay.example/", { upgrade: true }));
    assert.equal(r1.status, 403);
    const r2 = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED}:0`, { upgrade: true }));
    assert.equal(r2.status, 403);
    const r3 = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED}:70000`, { upgrade: true }));
    assert.equal(r3.status, 403);
    const r4 = await relay.fetch(req("https://relay.example/?dst=example.com:443", { upgrade: true }));
    assert.equal(r4.status, 403);
    assert.equal(calls, 0);
  });

  it("defaults to port 443 and passes it to connect", async () => {
    let seen = null;
    const relay = createRelay({
      connect(opts) { seen = opts; return okSocket(); },
      makeWebSocketPair: makeFakePairHolder().factory,
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED}`, { upgrade: true }));
    assert.equal(res.status, 101);
    assert.deepEqual(seen, { hostname: ALLOWED, port: 443 });
    await tick();
  });
});

describe("relay probe=1", () => {
  it("returns 200 with connected dst on success", async () => {
    const relay = createRelay({
      connect: () => okSocket(),
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED_DST}&probe=1`));
    assert.equal(res.status, 200);
    assert.equal(await res.text(), `connected ${ALLOWED_DST}`);
  });

  it("returns 502 when the connection fails", async () => {
    const relay = createRelay({
      connect: () => okSocket({ openedFails: true }),
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED_DST}&probe=1`));
    assert.equal(res.status, 502);
    const body = await res.text();
    assert.match(body, /connect failed/);
  });

  it("returns 502 when connect throws synchronously", async () => {
    const relay = createRelay({
      connect() { throw new Error("nope"); },
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED_DST}&probe=1`, { upgrade: true }));
    assert.equal(res.status, 502);
  });
});

describe("relay probe=2", () => {
  it("runs the MTProto handshake against a simulated socket", async () => {
    const written = [];
    // Encrypted peer answer: 16 zero bytes (decrypts deterministically).
    const fakeReply = new Uint8Array(16);
    const relay = createRelay({
      connect: () => okSocket({ written, chunks: [fakeReply] }),
      makeWebSocketPair() { throw new Error("must not be called"); },
    });
    const res = await relay.fetch(
      req(`https://relay.example/?dst=${ALLOWED_DST}&probe=2&dc=2`),
    );
    assert.equal(res.status, 200);
    const body = await res.text();
    assert.match(body, /^resp 16B plain: /);
    assert.match(body, /\nkey: [0-9a-f]{64}\niv: [0-9a-f]{32}\ncipher: [0-9a-f]{32}/);
    assert.ok(written.length >= 1);
    const total = written.reduce((n, c) => n + c.length, 0);
    assert.equal(total, 64 + 41);
  });
});

describe("relay 101 upgrade and piping", () => {
  it("upgrades allowed targets and forwards a frame in both directions", async () => {
    const written = [];
    const fromSocket = new Uint8Array([7, 8, 9]);
    const holder = makeFakePairHolder();
    const relay = createRelay({
      connect: () => okSocket({ written, chunks: [fromSocket] }),
      makeWebSocketPair: holder.factory,
    });
    const res = await relay.fetch(req(`https://relay.example/?dst=${ALLOWED_DST}`, { upgrade: true }));
    assert.equal(res.status, 101);
    assert.equal(holder.server.accepted, true);

    // Client -> socket direction through the serialised chain.
    holder.server.emitMessage(new TextEncoder().encode("ping").buffer);
    await tick(30);
    const flat = written.reduce((acc, c) => [...acc, ...Array.from(c)], []);
    assert.deepEqual(flat, [...new TextEncoder().encode("ping")]);

    // Socket -> client direction via server.send.
    await tick(30);
    assert.equal(holder.server.sent.length, 1);
    assert.deepEqual([...holder.server.sent[0]], [7, 8, 9]);
  });
});

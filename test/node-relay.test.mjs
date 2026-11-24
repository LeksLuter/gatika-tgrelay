import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";

import { createFrameParser, createRelayServer } from "../src/node-relay.mjs";

const ALLOWED = "91.108.4.5";

function maskedFrame(payload, opcode = 0x2, fin = true) {
  const body = Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  const length = body.length;
  let header;
  if (length < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = 0x80 | length;
  } else if (length < 65536) {
    header = Buffer.allocUnsafe(4);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = (fin ? 0x80 : 0) | (opcode & 0x0f);
  const out = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i++) out[i] = body[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, out]);
}

function takeUnmaskedFrame(buffer) {
  if (buffer.length < 2) return null;
  const opcode = buffer[0] & 0x0f;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buffer.length < 10) return null;
    length = Number(buffer.readBigUInt64BE(2));
    offset = 10;
  }
  if (buffer.length < offset + length) return null;
  return {
    opcode,
    payload: buffer.subarray(offset, offset + length),
    rest: buffer.subarray(offset + length),
  };
}

function withTimeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function get(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function closeAll(server) {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

test("parser accepts masked client frames and reassembles fragments", () => {
  const messages = [];
  const parser = createFrameParser({
    onMessage(payload, opcode) { messages.push({ payload, opcode }); },
    onControl() {},
    onError(code, reason) { assert.fail("unexpected parser error: " + code + " " + reason); },
  });

  parser.push(maskedFrame(Buffer.from("he"), 0x2, false));
  parser.push(maskedFrame(Buffer.from("llo"), 0x0, true));

  assert.equal(messages.length, 1);
  assert.equal(messages[0].payload.toString(), "hello");
  assert.equal(messages[0].opcode, 0x2);
});

test("parser rejects unmasked client frames", () => {
  let error = null;
  const parser = createFrameParser({
    onMessage() {},
    onControl() {},
    onError(code, reason) { error = { code, reason }; },
  });
  parser.push(Buffer.from([0x82, 0x01, 0x61]));
  assert.deepEqual(error, { code: 1002, reason: "client frame is not masked" });
});

test("HTTP diagnostics reject non-Telegram and non-WebSocket requests", async () => {
  const relay = createRelayServer({ connect: () => { throw new Error("must not connect"); } });
  const port = await listen(relay);
  try {
    const health = await get(port, "/health");
    assert.deepEqual(health, { status: 200, body: "ok" });

    const plain = await get(port, "/apiws?dst=" + ALLOWED + ":443");
    assert.equal(plain.status, 426);

    const forbidden = await get(port, "/apiws?dst=8.8.8.8:443");
    assert.equal(forbidden.status, 403);
  } finally {
    await closeAll(relay);
  }
});

test("probe=1 connects through the injected transport", async () => {
  const target = net.createServer((socket) => socket.end());
  const targetPort = await listen(target);
  const relay = createRelayServer({ connect: () => net.connect(targetPort, "127.0.0.1") });
  const port = await listen(relay);
  try {
    const result = await get(port, "/apiws?dst=" + ALLOWED + ":443&probe=1");
    assert.equal(result.status, 200);
    assert.equal(result.body, "connected " + ALLOWED + ":443");
  } finally {
    await closeAll(relay);
    await closeAll(target);
  }
});

test("WebSocket relay forwards bytes in both directions", async () => {
  const target = net.createServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  const targetPort = await listen(target);
  const relay = createRelayServer({
    connect: () => net.connect(targetPort, "127.0.0.1"),
    wsLifetimeMs: 0,
  });
  const port = await listen(relay);
  let client = null;
  try {
    const key = crypto.randomBytes(16).toString("base64");
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: "/apiws?dst=" + ALLOWED + ":443",
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
      },
    });
    req.on("response", (res) => { res.resume(); });
    req.on("error", () => {});
    req.end();
    const [res, socket, head] = await withTimeout(
      once(req, "upgrade"),
      2000,
      "upgrade timeout",
    );
    client = socket;
    assert.equal(res.statusCode, 101);
    const expected = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    assert.equal(res.headers["sec-websocket-accept"], expected);

    let buffer = Buffer.alloc(0);
    const framePromise = new Promise((resolve) => {
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        const frame = takeUnmaskedFrame(buffer);
        if (frame) resolve(frame.payload);
      });
    });
    if (head && head.length) buffer = Buffer.concat([buffer, head]);
    socket.write(maskedFrame(Buffer.from("hello over relay")));
    const payload = await withTimeout(framePromise, 2000, "frame timeout");
    assert.equal(payload.toString(), "hello over relay");
  } finally {
    if (client) client.destroy();
    if (relay.closeRelay) await relay.closeRelay();
    else await closeAll(relay);
    await closeAll(target);
  }
});

/**
 * Smoke-тест развёрнутого релея: открывает WebSocket, отправляет
 * MTProto-приветствие (obfuscated2 + req_pq_multi) и ждёт ответ DC.
 *
 * Запускается из GitHub Actions после деплоя — с машины в РФ
 * *.onrender.com недоступен.
 *
 *   RELAY_URL=wss://host/apiws?dst=149.154.167.51:443&dc=2 node scripts/smoke-relay.mjs
 */

import { buildHandshake } from "../src/mtproto-crypto.mjs";

const url =
  process.env.RELAY_URL ||
  "wss://gatika-tgrelay.onrender.com/apiws?dst=149.154.167.51:443&dc=2";

const random = crypto.getRandomValues(new Uint8Array(64));
const nonce = crypto.getRandomValues(new Uint8Array(16));
const { init, body } = await buildHandshake(random, 2, nonce);

const frame = new Uint8Array(init.length + body.length);
frame.set(init, 0);
frame.set(body, init.length);

console.log("smoke: " + url);
const timer = setTimeout(() => {
  console.error("smoke: timeout, ответа от DC нет");
  process.exit(1);
}, 25000);

const ws = new WebSocket(url);
ws.binaryType = "arraybuffer";

ws.onopen = () => {
  console.log("smoke: ws open, отправляю " + frame.length + " байт");
  ws.send(frame);
};

ws.onmessage = (event) => {
  const bytes = new Uint8Array(event.data);
  console.log(
    "smoke: got " + bytes.length + " bytes, head=" +
    Buffer.from(bytes.slice(0, 8)).toString("hex")
  );
  clearTimeout(timer);
  ws.close();
  process.exit(0);
};

ws.onerror = (event) => {
  console.error("smoke: ws error " + (event.message || ""));
};

ws.onclose = (event) => {
  console.error("smoke: ws closed code=" + event.code);
  process.exit(1);
};

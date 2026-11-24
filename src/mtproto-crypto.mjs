/**
 * MTProto obfuscation crypto primitives (offline, pure).
 *
 * Implements the exact handshake logic used by the Telegram relay probe:
 * - `ecbBlock`: single AES-256 block via AES-CBC with a zero IV.
 * - `ctrStream`: 16-byte big-endian counter keystream in 16-byte blocks.
 * - `xorBuf`: byte-wise XOR of two equal-length buffers.
 * - `buildHandshake`: deterministic 64-byte init + 41-byte framed
 *   `req_pq_multi` handshake from caller-supplied randomness.
 *
 * No sockets, no timers, no I/O. All randomness enters through arguments
 * so tests stay fully deterministic and offline.
 */

const ZERO_IV = new Uint8Array(16);
const REQ_PQ_MULTI = 3195965169;
const INIT_LEN = 64;
const FRAME_LEN = 41;
const MSG_LEN = 40;
const KEY_LEN = 32;
const IV_LEN = 16;
const NONCE_LEN = 16;
const MAX_STREAM_BYTES = 1048576;

export const REQ_PQ_MULTI_ID = REQ_PQ_MULTI;
export const LENGTH_PREFIX = 0x0a;

function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error("WebCrypto subtle is not available");
  return s;
}

function assertU8(value, name) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

/**
 * Encrypt one 16-byte block with AES-256, emulating ECB via CBC + zero IV.
 *
 * WebCrypto AES-CBC applies PKCS#7 padding, so a 16-byte plaintext yields
 * 32 bytes of ciphertext; the first block equals the raw ECB encryption.
 *
 * @param {Uint8Array} key - 32-byte AES key.
 * @param {Uint8Array} block - 16-byte plaintext block.
 * @returns {Promise<Uint8Array>} 16-byte ciphertext block.
 */
export async function ecbBlock(key, block) {
  assertU8(key, "key");
  assertU8(block, "block");
  if (key.length !== KEY_LEN) {
    throw new RangeError(`key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (block.length !== IV_LEN) {
    throw new RangeError(`block must be ${IV_LEN} bytes, got ${block.length}`);
  }
  const k = await subtle().importKey("raw", key, "AES-CBC", false, ["encrypt"]);
  const buf = await subtle().encrypt({ name: "AES-CBC", iv: ZERO_IV }, k, block);
  return new Uint8Array(buf, 0, IV_LEN);
}

/**
 * Generate `total` keystream bytes: AES-CTR with a 16-byte big-endian counter.
 *
 * The counter starts at `iv` and is incremented by one (big-endian with
 * carry) after every 16-byte block, matching the relay probe logic.
 * Inputs are never mutated.
 *
 * @param {Uint8Array} key - 32-byte AES key.
 * @param {Uint8Array} iv - 16-byte initial counter value.
 * @param {number} total - Number of keystream bytes (>= 0).
 * @returns {Promise<Uint8Array>} Keystream of length `total`.
 */
export async function ctrStream(key, iv, total) {
  assertU8(key, "key");
  assertU8(iv, "iv");
  if (key.length !== KEY_LEN) {
    throw new RangeError(`key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (iv.length !== IV_LEN) {
    throw new RangeError(`iv must be ${IV_LEN} bytes, got ${iv.length}`);
  }
  if (!Number.isInteger(total) || total < 0) {
    throw new RangeError(`total must be a non-negative integer, got ${total}`);
  }
  if (total > MAX_STREAM_BYTES) {
    throw new RangeError(`total exceeds limit ${MAX_STREAM_BYTES}`);
  }
  const ks = new Uint8Array(total);
  const counter = Uint8Array.from(iv);
  for (let off = 0; off < total; off += 16) {
    const block = await ecbBlock(key, counter);
    const n = Math.min(16, total - off);
    ks.set(block.subarray(0, n), off);
    let carry = 1;
    for (let i = 15; i >= 0; i--) {
      carry += counter[i];
      counter[i] = carry & 255;
      carry >>= 8;
    }
  }
  return ks;
}

/**
 * Byte-wise XOR of two equal-length buffers.
 *
 * @param {Uint8Array} a - First operand.
 * @param {Uint8Array} b - Second operand, same length as `a`.
 * @returns {Uint8Array} New buffer with `a[i] ^ b[i]`.
 */
export function xorBuf(a, b) {
  assertU8(a, "a");
  assertU8(b, "b");
  if (a.length !== b.length) {
    throw new RangeError(`xorBuf length mismatch: ${a.length} vs ${b.length}`);
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function normalizeDcNum(dcNum) {
  if (typeof dcNum !== "number" || !Number.isFinite(dcNum) || !Number.isInteger(dcNum)) {
    throw new TypeError(`dcNum must be an integer, got ${String(dcNum)}`);
  }
  if (dcNum < 0 || dcNum > 65535) {
    throw new RangeError(`dcNum must be in [0, 65535], got ${dcNum}`);
  }
  return dcNum;
}

/**
 * Build the MTProto obfuscation handshake buffers.
 *
 * Mirrors the relay `mtprotoProbe` preamble exactly:
 * - copies `random64`, guards byte 0 against `0xEF` and a leading `"HEAD"`,
 * - forces bytes 56..59 to `0xEF` and stores `dcNum` little-endian in
 *   bytes 60/61,
 * - derives `key = rnd[8..40)` and `iv = rnd[40..56)`,
 * - frames a 40-byte `req_pq_multi` payload (`len=20` at offset 16,
 *   constructor id at offset 20, `nonce` at offset 24) with a `0x0A`
 *   single-byte length prefix (41 bytes total),
 * - encrypts with `ctrStream(key, iv, 64 + 41)`: the first 56 init bytes
 *   stay plaintext, the last 8 init bytes and the whole frame are XORed
 *   with the keystream.
 *
 * Never mutates `random64` or `nonce`.
 *
 * @param {Uint8Array} random64 - 64 bytes of caller-supplied randomness.
 * @param {number} dcNum - DC number, integer in [0, 65535].
 * @param {Uint8Array} nonce - 16-byte nonce placed at msg offset 24.
 * @returns {Promise<{init: Uint8Array, body: Uint8Array, key: Uint8Array, iv: Uint8Array}>}
 */
export async function buildHandshake(random64, dcNum, nonce) {
  assertU8(random64, "random64");
  assertU8(nonce, "nonce");
  if (random64.length !== INIT_LEN) {
    throw new RangeError(`random64 must be ${INIT_LEN} bytes, got ${random64.length}`);
  }
  if (nonce.length !== NONCE_LEN) {
    throw new RangeError(`nonce must be ${NONCE_LEN} bytes, got ${nonce.length}`);
  }
  const dc = normalizeDcNum(dcNum);

  const rnd = Uint8Array.from(random64);
  if (rnd[0] === 239) rnd[0] = 66;
  if (
    rnd[0] === 0x48 &&
    rnd[1] === 0x45 &&
    rnd[2] === 0x41 &&
    rnd[3] === 0x44
  ) {
    rnd[0] = 66;
  }
  rnd[56] = 239;
  rnd[57] = 239;
  rnd[58] = 239;
  rnd[59] = 239;
  rnd[60] = dc & 255;
  rnd[61] = (dc >> 8) & 255;

  const key = rnd.slice(8, 40);
  const iv = rnd.slice(40, 56);

  const msg = new Uint8Array(MSG_LEN);
  const dv = new DataView(msg.buffer);
  dv.setUint32(16, 20, true);
  dv.setUint32(20, REQ_PQ_MULTI, true);
  msg.set(nonce, 24);

  const frame = new Uint8Array(FRAME_LEN);
  frame[0] = LENGTH_PREFIX;
  frame.set(msg, 1);

  const ksFull = await ctrStream(key, iv, INIT_LEN + frame.length);

  const init = new Uint8Array(INIT_LEN);
  init.set(rnd.subarray(0, 56), 0);
  init.set(xorBuf(rnd.subarray(56, 64), ksFull.subarray(56, 64)), 56);
  const body = xorBuf(frame, ksFull.subarray(64));

  return { init, body, key, iv };
}

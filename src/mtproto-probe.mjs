/**
 * MTProto diagnostic probe (I/O layer).
 *
 * Performs the obfuscated MTProto handshake against an already-connected
 * socket and returns a single human-readable diagnostic string.
 * Pure handshake bytes come from `buildHandshake` in
 * `./mtproto-crypto.mjs`; this module only owns randomness, socket I/O,
 * the 8-second read timeout and response decryption.
 *
 * The function never throws and never rejects: every failure mode
 * (missing socket, connect failure, handshake failure, write failure,
 * read failure, empty response) is mapped to a diagnostic string so the
 * relay can always answer `probe=2` with HTTP 200.
 */

import { buildHandshake, ctrStream, xorBuf } from "./mtproto-crypto.mjs";

const PROBE_TIMEOUT_MS = 8000;
const PLAIN_PREVIEW_LEN = 40;
const RANDOM_LEN = 64;
const NONCE_LEN = 16;

/**
 * Encode bytes as lowercase hex without separators.
 *
 * @param {Uint8Array} bytes - Input bytes.
 * @returns {string} Hex string (two chars per byte).
 */
function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Extract a readable message from an unknown thrown value.
 *
 * @param {unknown} err - Thrown value.
 * @returns {string} Message text, never empty.
 */
function errText(err) {
  if (err instanceof Error && typeof err.message === "string" && err.message !== "") {
    return err.message;
  }
  if (typeof err === "string" && err !== "") return err;
  try {
    const s = String(err);
    return s === "" ? "unknown error" : s;
  } catch {
    return "unknown error";
  }
}

/**
 * Normalise a socket read chunk to a Uint8Array.
 *
 * @param {unknown} value - Raw `read()` value.
 * @returns {Uint8Array|null} Byte view or null when not convertible.
 */
function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) {
    return new Uint8Array(value);
  }
  if (value != null && typeof value === "object") {
    const v = /** @type {{ buffer?: unknown, byteOffset?: unknown, byteLength?: unknown, length?: unknown }} */ (value);
    // Accept DataView and typed-array views.
    if (ArrayBuffer.isView(v)) {
      return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    }
  }
  return null;
}

/**
 * Run the MTProto obfuscation handshake and describe the peer answer.
 *
 * Steps:
 * 1. Await `socket.opened` (connect failure -> diagnostic string).
 * 2. Generate 64 random bytes + 16-byte nonce, build `{ init, body, key, iv }`
 *    via `buildHandshake(random64, dcNum, nonce)`.
 * 3. Write `init || body` to `socket.writable`.
 * 4. Read one chunk from `socket.readable` with an 8-second timeout
 *    implemented via `reader.cancel()`.
 * 5. Decrypt with the byte-reversed key and byte-reversed IV and format
 *    `resp <n>B plain: <hex>\nkey: <hex>\niv: <hex>\ncipher: <hex>`.
 *
 * @param {{ opened?: Promise<unknown>, writable?: { getWriter?: () => { write: (c: Uint8Array) => Promise<unknown>, releaseLock?: () => void } }, readable?: { getReader?: () => { read: () => Promise<{ value?: unknown, done?: boolean }>, cancel?: () => unknown, releaseLock?: () => void } }, close?: () => unknown }} socket - Connected TCP socket.
 * @param {number} dcNum - Data-center number, forwarded to `buildHandshake`.
 * @returns {Promise<string>} Diagnostic line; never rejects.
 */
export async function mtprotoProbe(socket, dcNum) {
  try {
    if (!socket || typeof socket !== "object") {
      return "connect failed: invalid socket";
    }
    try {
      await socket.opened;
    } catch (err) {
      return "connect failed: " + errText(err);
    }

    const cryptoObj = globalThis.crypto;
    if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
      return "handshake failed: crypto.getRandomValues is not available";
    }

    let handshake;
    try {
      const random64 = cryptoObj.getRandomValues(new Uint8Array(RANDOM_LEN));
      const nonce = cryptoObj.getRandomValues(new Uint8Array(NONCE_LEN));
      handshake = await buildHandshake(random64, dcNum, nonce);
    } catch (err) {
      return "handshake failed: " + errText(err);
    }
    const { init, body, key, iv } = handshake;

    const payload = new Uint8Array(init.length + body.length);
    payload.set(init, 0);
    payload.set(body, init.length);

    let writer = null;
    try {
      if (!socket.writable || typeof socket.writable.getWriter !== "function") {
        return "write failed: socket.writable is not available";
      }
      writer = socket.writable.getWriter();
      await writer.write(payload);
    } catch (err) {
      return "write failed: " + errText(err);
    } finally {
      if (writer && typeof writer.releaseLock === "function") {
        try {
          writer.releaseLock();
        } catch {
          // Ignore lock-release errors; the diagnostic string below matters.
        }
      }
    }

    let reader = null;
    let timer = undefined;
    try {
      if (!socket.readable || typeof socket.readable.getReader !== "function") {
        return "read failed: socket.readable is not available";
      }
      reader = socket.readable.getReader();
      timer = setTimeout(() => {
        try {
          if (reader && typeof reader.cancel === "function") reader.cancel();
        } catch {
          // cancel() best-effort only.
        }
      }, PROBE_TIMEOUT_MS);
      const { value, done } = await reader.read();
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      if (done) return "read done, 0 bytes";
      const bytes = toBytes(value);
      if (!bytes || bytes.byteLength === 0) return "read done, 0 bytes";
      const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const rkey = Uint8Array.from(key).reverse();
      const riv = Uint8Array.from(iv).reverse();
      let plain;
      try {
        const ksR = await ctrStream(rkey, riv, data.length);
        plain = xorBuf(data, ksR);
      } catch (err) {
        return "read failed: " + errText(err);
      }
      const preview = plain.subarray(0, Math.min(PLAIN_PREVIEW_LEN, plain.length));
      return (
        "resp " +
        data.length +
        "B plain: " +
        toHex(preview) +
        "\nkey: " +
        toHex(key) +
        "\niv: " +
        toHex(iv) +
        "\ncipher: " +
        toHex(data)
      );
    } catch (err) {
      if (timer !== undefined) {
        try {
          clearTimeout(timer);
        } catch {
          // Ignore timer errors.
        }
      }
      return "read failed: " + errText(err);
    } finally {
      if (reader && typeof reader.releaseLock === "function") {
        try {
          reader.releaseLock();
        } catch {
          // Ignore lock-release errors.
        }
      }
    }
  } catch (err) {
    return "read failed: " + errText(err);
  }
}

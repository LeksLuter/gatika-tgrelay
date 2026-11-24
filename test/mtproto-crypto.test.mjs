import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildHandshake, ctrStream, ecbBlock, xorBuf } from "../src/mtproto-crypto.mjs";

function fixedBytes(length, start = 0) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (start + i * 37 + 11) & 255;
  // Keep byte 0 away from the 0xEF / HEAD guards unless a test wants them.
  if (length > 0 && out[0] === 239) out[0] = 1;
  if (length >= 4 && out[0] === 0x48 && out[1] === 0x45 && out[2] === 0x41 && out[3] === 0x44) {
    out[0] = 1;
  }
  return out;
}

function headBytes() {
  const out = fixedBytes(64, 7);
  out[0] = 0x48; // H
  out[1] = 0x45; // E
  out[2] = 0x41; // A
  out[3] = 0x44; // D
  return out;
}

describe("ecbBlock", () => {
  it("returns 16 bytes and is deterministic", async () => {
    const key = fixedBytes(32, 1);
    const block = fixedBytes(16, 5);
    const a = await ecbBlock(key, block);
    const b = await ecbBlock(key, block);
    assert.equal(a.length, 16);
    assert.deepEqual([...a], [...b]);
  });

  it("differs for different keys or blocks", async () => {
    const key = fixedBytes(32, 1);
    const otherKey = Uint8Array.from(key);
    otherKey[0] ^= 1;
    const block = fixedBytes(16, 5);
    const otherBlock = Uint8Array.from(block);
    otherBlock[15] ^= 1;
    const base = await ecbBlock(key, block);
    const diffKey = await ecbBlock(otherKey, block);
    const diffBlock = await ecbBlock(key, otherBlock);
    assert.notDeepEqual([...base], [...diffKey]);
    assert.notDeepEqual([...base], [...diffBlock]);
  });

  it("does not mutate inputs", async () => {
    const key = fixedBytes(32, 9);
    const block = fixedBytes(16, 3);
    const keyBefore = [...key];
    const blockBefore = [...block];
    await ecbBlock(key, block);
    assert.deepEqual([...key], keyBefore);
    assert.deepEqual([...block], blockBefore);
  });

  it("rejects wrong sizes", async () => {
    await assert.rejects(() => ecbBlock(new Uint8Array(16), new Uint8Array(16)));
    await assert.rejects(() => ecbBlock(new Uint8Array(32), new Uint8Array(8)));
    await assert.rejects(() => ecbBlock("x", new Uint8Array(16)));
  });
});

describe("ctrStream", () => {
  it("has the requested length and handles zero length", async () => {
    const key = fixedBytes(32, 2);
    const iv = fixedBytes(16, 4);
    assert.equal((await ctrStream(key, iv, 0)).length, 0);
    assert.equal((await ctrStream(key, iv, 1)).length, 1);
    assert.equal((await ctrStream(key, iv, 16)).length, 16);
    assert.equal((await ctrStream(key, iv, 17)).length, 17);
    assert.equal((await ctrStream(key, iv, 105)).length, 105);
  });

  it("is deterministic for the same key and iv", async () => {
    const key = fixedBytes(32, 2);
    const iv = fixedBytes(16, 4);
    const a = await ctrStream(key, iv, 64);
    const b = await ctrStream(key, iv, 64);
    assert.deepEqual([...a], [...b]);
  });

  it("prefix property: shorter stream is a prefix of the longer one", async () => {
    const key = fixedBytes(32, 12);
    const iv = fixedBytes(16, 21);
    const short = await ctrStream(key, iv, 16);
    const long = await ctrStream(key, iv, 48);
    assert.deepEqual([...long.subarray(0, 16)], [...short]);
  });

  it("produces different streams for different IVs", async () => {
    const key = fixedBytes(32, 2);
    const ivA = new Uint8Array(16);
    const ivB = new Uint8Array(16);
    ivB[15] = 1;
    const a = await ctrStream(key, ivA, 64);
    const b = await ctrStream(key, ivB, 64);
    assert.notDeepEqual([...a], [...b]);
  });

  it("produces different streams for different keys", async () => {
    const iv = fixedBytes(16, 4);
    const keyA = fixedBytes(32, 2);
    const keyB = Uint8Array.from(keyA);
    keyB[31] ^= 0xff;
    const a = await ctrStream(keyA, iv, 32);
    const b = await ctrStream(keyB, iv, 32);
    assert.notDeepEqual([...a], [...b]);
  });

  it("does not mutate key or iv", async () => {
    const key = fixedBytes(32, 6);
    const iv = fixedBytes(16, 8);
    const keyBefore = [...key];
    const ivBefore = [...iv];
    await ctrStream(key, iv, 48);
    assert.deepEqual([...key], keyBefore);
    assert.deepEqual([...iv], ivBefore);
  });

  it("rejects invalid sizes", async () => {
    await assert.rejects(() => ctrStream(new Uint8Array(16), new Uint8Array(16), 16));
    await assert.rejects(() => ctrStream(new Uint8Array(32), new Uint8Array(8), 16));
    await assert.rejects(() => ctrStream(new Uint8Array(32), new Uint8Array(16), -1));
    await assert.rejects(() => ctrStream(new Uint8Array(32), new Uint8Array(16), 1.5));
  });
});

describe("xorBuf", () => {
  it("xors byte-wise and round-trips", () => {
    const a = fixedBytes(41, 3);
    const k = fixedBytes(41, 99);
    const c = xorBuf(a, k);
    assert.equal(c.length, 41);
    for (let i = 0; i < a.length; i++) assert.equal(c[i], (a[i] ^ k[i]) & 255);
    assert.deepEqual([...xorBuf(c, k)], [...a]);
  });

  it("xor with zeros is identity, xor with self is zero", () => {
    const a = fixedBytes(24, 17);
    assert.deepEqual([...xorBuf(a, new Uint8Array(24))], [...a]);
    assert.deepEqual([...xorBuf(a, a)], [...new Uint8Array(24)]);
  });

  it("does not mutate inputs and returns a new buffer", () => {
    const a = fixedBytes(8, 1);
    const b = fixedBytes(8, 50);
    const aBefore = [...a];
    const bBefore = [...b];
    const out = xorBuf(a, b);
    assert.deepEqual([...a], aBefore);
    assert.deepEqual([...b], bBefore);
    assert.notEqual(out, a);
    assert.notEqual(out, b);
  });

  it("rejects length mismatch and non-bytes", () => {
    assert.throws(() => xorBuf(new Uint8Array(4), new Uint8Array(5)), RangeError);
    assert.throws(() => xorBuf("ab", new Uint8Array(2)), TypeError);
  });
});

describe("buildHandshake", () => {
  it("returns init(64), body(41), key(32), iv(16) with expected framing", async () => {
    const random64 = fixedBytes(64, 10);
    const nonce = fixedBytes(16, 200);
    const res = await buildHandshake(random64, 2, nonce);
    assert.equal(res.init.length, 64);
    assert.equal(res.body.length, 41);
    assert.equal(res.key.length, 32);
    assert.equal(res.iv.length, 16);

    // First 56 init bytes are the guarded randomness in plaintext.
    assert.deepEqual([...res.init.subarray(0, 56)], [...guarded(random64, 2).subarray(0, 56)]);
    // Key / IV derivation windows.
    assert.deepEqual([...res.key], [...guarded(random64, 2).subarray(8, 40)]);
    assert.deepEqual([...res.iv], [...guarded(random64, 2).subarray(40, 56)]);

    // Decrypt tail: init[56..64] xor keystream[56..64] must expose EF bytes + dc LE.
    const ks = await ctrStream(res.key, res.iv, 64 + 41);
    const tail = xorBuf(res.init.subarray(56, 64), ks.subarray(56, 64));
    assert.deepEqual([...tail.subarray(0, 4)], [239, 239, 239, 239]);
    assert.equal(tail[4], 2);
    assert.equal(tail[5], 0);

    // Decrypt body: frame must carry 0x0A prefix, len=20, req_pq_multi id, nonce.
    const frame = xorBuf(res.body, ks.subarray(64));
    assert.equal(frame[0], 0x0a);
    const dv = new DataView(frame.buffer, frame.byteOffset + 1, 40);
    assert.equal(dv.getUint32(16, true), 20);
    assert.equal(dv.getUint32(20, true), 3195965169);
    assert.deepEqual([...frame.subarray(25, 41)], [...nonce]);
  });

  function guarded(input, dc) {
    const rnd = Uint8Array.from(input);
    if (rnd[0] === 239) rnd[0] = 66;
    if (rnd[0] === 0x48 && rnd[1] === 0x45 && rnd[2] === 0x41 && rnd[3] === 0x44) rnd[0] = 66;
    rnd[56] = 239;
    rnd[57] = 239;
    rnd[58] = 239;
    rnd[59] = 239;
    rnd[60] = dc & 255;
    rnd[61] = (dc >> 8) & 255;
    return rnd;
  }

  it("encodes dcNum little-endian in bytes 60/61 (after decrypting the tail)", async () => {
    const random64 = fixedBytes(64, 30);
    const nonce = fixedBytes(16, 40);
    for (const dc of [0, 1, 2, 256, 511, 65535]) {
      const res = await buildHandshake(random64, dc, nonce);
      const ks = await ctrStream(res.key, res.iv, 105);
      const tail = xorBuf(res.init.subarray(56, 64), ks.subarray(56, 64));
      assert.equal(tail[4], dc & 255, `dc=${dc} low byte`);
      assert.equal(tail[5], (dc >> 8) & 255, `dc=${dc} high byte`);
    }
  });

  it("is deterministic for identical random64, dcNum and nonce", async () => {
    const random64 = fixedBytes(64, 10);
    const nonce = fixedBytes(16, 200);
    const a = await buildHandshake(random64, 2, nonce);
    const b = await buildHandshake(random64, 2, nonce);
    assert.deepEqual([...a.init], [...b.init]);
    assert.deepEqual([...a.body], [...b.body]);
    assert.deepEqual([...a.key], [...b.key]);
    assert.deepEqual([...a.iv], [...b.iv]);
  });

  it("changes the body when the nonce changes", async () => {
    const random64 = fixedBytes(64, 10);
    const n1 = new Uint8Array(16);
    const n2 = new Uint8Array(16);
    n2[0] = 1;
    const a = await buildHandshake(random64, 2, n1);
    const b = await buildHandshake(random64, 2, n2);
    assert.notDeepEqual([...a.body], [...b.body]);
  });

  it("guards 0xEF first byte and HEAD magic", async () => {
    const nonce = fixedBytes(16, 5);
    const ef = fixedBytes(64, 11);
    ef[0] = 239;
    const r1 = await buildHandshake(ef, 2, nonce);
    assert.notEqual(r1.init[0], 239);
    assert.equal(r1.init[0], 66);

    const head = headBytes();
    const r2 = await buildHandshake(head, 2, nonce);
    assert.equal(r2.init[0], 66);
    // Remaining HEAD bytes stay intact in the plaintext prefix.
    assert.equal(r2.init[1], 0x45);
    assert.equal(r2.init[2], 0x41);
    assert.equal(r2.init[3], 0x44);
  });

  it("never mutates the input buffers", async () => {
    const random64 = fixedBytes(64, 10);
    random64[0] = 239; // exercise the guard path and still require immutability
    const nonce = fixedBytes(16, 200);
    const rndBefore = [...random64];
    const nonceBefore = [...nonce];
    await buildHandshake(random64, 2, nonce);
    assert.deepEqual([...random64], rndBefore);
    assert.deepEqual([...nonce], nonceBefore);
  });

  it("rejects invalid inputs", async () => {
    const ok64 = fixedBytes(64, 1);
    const ok16 = fixedBytes(16, 1);
    await assert.rejects(() => buildHandshake(new Uint8Array(63), 2, ok16));
    await assert.rejects(() => buildHandshake(new Uint8Array(65), 2, ok16));
    await assert.rejects(() => buildHandshake(ok64, 2, new Uint8Array(15)));
    await assert.rejects(() => buildHandshake(ok64, 1.5, ok16));
    await assert.rejects(() => buildHandshake(ok64, -1, ok16));
    await assert.rejects(() => buildHandshake(ok64, 65536, ok16));
    await assert.rejects(() => buildHandshake("x", 2, ok16));
  });
});

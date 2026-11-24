import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TELEGRAM_NETS, ipToInt, isAllowedHost, parseDst } from "../src/telegram-nets.mjs";

describe("TELEGRAM_NETS shape", () => {
  it("contains the nine expected networks", () => {
    assert.equal(TELEGRAM_NETS.length, 9);
    assert.deepEqual([...TELEGRAM_NETS], [
      ["91.108.4.0", 22],
      ["91.108.8.0", 22],
      ["91.108.12.0", 22],
      ["91.108.16.0", 22],
      ["91.108.20.0", 22],
      ["91.108.56.0", 22],
      ["91.105.192.0", 23],
      ["149.154.160.0", 20],
      ["185.76.151.0", 24],
    ]);
  });
});

describe("ipToInt strict validation", () => {
  it("parses boundary values", () => {
    assert.equal(ipToInt("0.0.0.0"), 0);
    assert.equal(ipToInt("255.255.255.255"), 4294967295);
    assert.equal(ipToInt("91.108.4.0"), 1533805568);
    assert.equal(ipToInt("1.2.3.4"), 1 * 16777216 + 2 * 65536 + 3 * 256 + 4);
  });

  it("rejects malformed IPv4 strings", () => {
    assert.equal(ipToInt(""), null);
    assert.equal(ipToInt("1.2.3"), null);
    assert.equal(ipToInt("1.2.3.4.5"), null);
    assert.equal(ipToInt("256.0.0.1"), null);
    assert.equal(ipToInt("-1.0.0.0"), null);
    assert.equal(ipToInt("1.2.3.999"), null);
    assert.equal(ipToInt("a.b.c.d"), null);
    assert.equal(ipToInt("1.2.3.abc"), null);
    assert.equal(ipToInt("1.2.3.4."), null);
    assert.equal(ipToInt(".1.2.3.4"), null);
    assert.equal(ipToInt("1..3.4"), null);
    assert.equal(ipToInt("1.2.3.4 "), null);
    assert.equal(ipToInt(" 1.2.3.4"), null);
    assert.equal(ipToInt("1.2.3.4\n"), null);
    assert.equal(ipToInt("0x1.0x2.0x3.0x4"), null);
    assert.equal(ipToInt("1.2.3.04x"), null);
    assert.equal(ipToInt("1,2,3,4"), null);
    assert.equal(ipToInt(null), null);
    assert.equal(ipToInt(undefined), null);
    assert.equal(ipToInt(12345), null);
    assert.equal(ipToInt("1.2.3.4:443"), null);
  });
});

describe("isAllowedHost boundaries", () => {
  const cases = [
    // 91.108.4.0/22 ... 91.108.20.0/22 идут подряд: адрес после
    // одной подсети (например, 91.108.8.0) уже принадлежит следующей.
    // Для проверки "после" берём первый адрес общего разрыва до 91.108.56.0.
    // До и после непрерывного блока 91.108.4.0/22…91.108.20.0/22
    // лежат только чужие адреса из общего разрыва.
    { base: "91.108.4.0", first: "91.108.4.0", last: "91.108.7.255", before: "91.108.3.255", after: "91.108.24.1" },
    { base: "91.108.8.0", first: "91.108.8.0", last: "91.108.11.255", before: "91.108.24.1", after: "91.108.55.1" },
    { base: "91.108.12.0", first: "91.108.12.0", last: "91.108.15.255", before: "91.108.24.1", after: "91.108.55.1" },
    { base: "91.108.16.0", first: "91.108.16.0", last: "91.108.19.255", before: "91.108.24.1", after: "91.108.55.1" },
    { base: "91.108.20.0", first: "91.108.20.0", last: "91.108.23.255", before: "91.108.24.1", after: "91.108.55.1" },
    { base: "91.108.56.0", first: "91.108.56.0", last: "91.108.59.255", before: "91.108.55.255", after: "91.108.60.0" },
    { base: "91.105.192.0", first: "91.105.192.0", last: "91.105.193.255", before: "91.105.191.255", after: "91.105.194.0" },
    { base: "149.154.160.0", first: "149.154.160.0", last: "149.154.175.255", before: "149.154.159.255", after: "149.154.176.0" },
    { base: "185.76.151.0", first: "185.76.151.0", last: "185.76.151.255", before: "185.76.150.255", after: "185.76.152.0" },
  ];

  for (const c of cases) {
    it(`allows ${c.first} and ${c.last}, rejects ${c.before} and ${c.after} (${c.base})`, () => {
      assert.equal(isAllowedHost(c.first), true);
      assert.equal(isAllowedHost(c.last), true);
      assert.equal(isAllowedHost(c.before), false);
      assert.equal(isAllowedHost(c.after), false);
    });
  }

  it("accepts the first address of an adjacent Telegram network", () => {
    // Это продолжение разрешённого диапазона, а не выход за него.
    assert.equal(isAllowedHost("91.108.8.0"), true);
    assert.equal(isAllowedHost("91.108.12.0"), true);
    assert.equal(isAllowedHost("91.108.16.0"), true);
    assert.equal(isAllowedHost("91.108.20.0"), true);
  });

  it("allows a middle address of each network", () => {
    assert.equal(isAllowedHost("91.108.5.10"), true);
    assert.equal(isAllowedHost("91.108.9.1"), true);
    assert.equal(isAllowedHost("91.108.13.200"), true);
    assert.equal(isAllowedHost("91.108.17.1"), true);
    assert.equal(isAllowedHost("91.108.21.254"), true);
    assert.equal(isAllowedHost("91.108.57.100"), true);
    assert.equal(isAllowedHost("91.105.192.200"), true);
    assert.equal(isAllowedHost("149.154.167.10"), true);
    assert.equal(isAllowedHost("185.76.151.100"), true);
  });

  it("rejects gaps between Telegram ranges", () => {
    // Between 91.108.23.x and 91.108.56.x there is a gap.
    assert.equal(isAllowedHost("91.108.24.1"), false);
    assert.equal(isAllowedHost("91.108.55.1"), false);
    assert.equal(isAllowedHost("8.8.8.8"), false);
    assert.equal(isAllowedHost("1.1.1.1"), false);
    assert.equal(isAllowedHost("0.0.0.0"), false);
    assert.equal(isAllowedHost("255.255.255.255"), false);
  });

  it("rejects hostnames instead of IPs (no DNS resolution)", () => {
    assert.equal(isAllowedHost("example.com"), false);
    assert.equal(isAllowedHost("telegram.org"), false);
    assert.equal(isAllowedHost("localhost"), false);
    assert.equal(isAllowedHost(""), false);
    assert.equal(isAllowedHost("91.108.4"), false);
    assert.equal(isAllowedHost("91.108.4.0:443"), false);
  });
});

describe("parseDst", () => {
  it("defaults to port 443 when absent", () => {
    assert.deepEqual(parseDst("91.108.4.5"), { host: "91.108.4.5", port: 443 });
    assert.deepEqual(parseDst("149.154.167.10"), { host: "149.154.167.10", port: 443 });
  });

  it("parses explicit valid ports", () => {
    assert.deepEqual(parseDst("91.108.4.5:443"), { host: "91.108.4.5", port: 443 });
    assert.deepEqual(parseDst("91.108.4.5:80"), { host: "91.108.4.5", port: 80 });
    assert.deepEqual(parseDst("91.108.4.5:1"), { host: "91.108.4.5", port: 1 });
    assert.deepEqual(parseDst("91.108.4.5:65535"), { host: "91.108.4.5", port: 65535 });
  });

  it("rejects port 0 and port 70000", () => {
    assert.equal(parseDst("91.108.4.5:0"), null);
    assert.equal(parseDst("91.108.4.5:70000"), null);
    assert.equal(parseDst("91.108.4.5:65536"), null);
  });

  it("rejects missing or malformed hosts and ports", () => {
    assert.equal(parseDst(""), null);
    assert.equal(parseDst("   "), null);
    assert.equal(parseDst(":443"), null);
    assert.equal(parseDst(":"), null);
    assert.equal(parseDst("91.108.4.5:"), null);
    assert.equal(parseDst("91.108.4.5:abc"), null);
    assert.equal(parseDst("91.108.4.5:-1"), null);
    assert.equal(parseDst("91.108.4.5:443.5"), null);
    assert.equal(parseDst("91.108.4.5: 443"), null);
    assert.equal(parseDst("91.108.4.5:443:1"), null);
    assert.equal(parseDst("91.108.4.5:443 "), null);
    assert.equal(parseDst(null), null);
    assert.equal(parseDst(undefined), null);
  });
});

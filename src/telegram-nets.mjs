/**
 * Telegram network allowlist and `dst` parser.
 *
 * Pure module: no I/O, no sockets, no DNS. Hostnames are never resolved;
 * only dotted-quad IPv4 addresses that fall inside TELEGRAM_NETS are allowed.
 */

export const TELEGRAM_NETS = Object.freeze([
  Object.freeze(["91.108.4.0", 22]),
  Object.freeze(["91.108.8.0", 22]),
  Object.freeze(["91.108.12.0", 22]),
  Object.freeze(["91.108.16.0", 22]),
  Object.freeze(["91.108.20.0", 22]),
  Object.freeze(["91.108.56.0", 22]),
  Object.freeze(["91.105.192.0", 23]),
  Object.freeze(["149.154.160.0", 20]),
  Object.freeze(["185.76.151.0", 24]),
]);

const OCTET_RE = /^(0|[1-9][0-9]{0,2})$/;
const PORT_RE = /^[0-9]+$/;
export const DEFAULT_PORT = 443;
export const MIN_PORT = 1;
export const MAX_PORT = 65535;

/**
 * Strictly parse a dotted-quad IPv4 address to an unsigned 32-bit integer.
 *
 * @param {unknown} ip - Candidate address string.
 * @returns {number | null} Unsigned int in [0, 2**32 - 1], or null if invalid.
 */
export function ipToInt(ip) {
  if (typeof ip !== "string") return null;
  if (ip === "") return null;
  if (ip !== ip.trim()) return null;
  if (/\s/.test(ip)) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (part === "" || !OCTET_RE.test(part)) return null;
    if (part.length > 1 && part[0] === "0") return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = ((value * 256) + n) >>> 0;
  }
  return value >>> 0;
}
/**
 * Decide whether a host string is an IPv4 address inside a Telegram network.
 *
 * Range membership is inclusive of the network base and exclusive of
 * `base + 2 ** (32 - prefixBits)`. Anything that is not a valid IPv4
 * address (including DNS hostnames) returns false.
 *
 * @param {unknown} host - Candidate host string.
 * @returns {boolean} True when the host is an allowed Telegram IP.
 */
export function isAllowedHost(host) {
  const ip = ipToInt(typeof host === "string" ? host : "");
  if (ip === null) return false;
  return TELEGRAM_NETS.some(([base, bits]) => {
    const net = ipToInt(base);
    if (net === null) return false;
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const size = 2 ** (32 - bits);
    return ip >= net && ip < net + size;
  });
}

/** Backwards-compatible alias for the pre-refactor `allowed(host)` name. */
export const allowed = isAllowedHost;

/**
 * Parse a relay `dst` value of the form `host` or `host:port`.
 *
 * - Missing port defaults to 443.
 * - Port must be a decimal integer in [1, 65535]; otherwise null.
 * - Host must be a non-empty string without whitespace or extra colons;
 *   an empty or malformed host yields null. IP membership itself is
 *   checked separately via {@link isAllowedHost}.
 *
 * @param {unknown} dst - Raw `dst` query value.
 * @returns {{ host: string, port: number } | null} Parsed destination or null.
 */
export function parseDst(dst) {
  if (typeof dst !== "string") return null;
  if (dst === "") return null;
  if (/\s/.test(dst)) return null;
  if (dst !== dst.trim()) return null;
  const raw = dst;
  const parts = raw.split(":");
  if (parts.length > 2) return null;
  const host = parts[0];
  const portRaw = parts.length === 2 ? parts[1] : "";
  if (host === "") return null;
  if (host.includes(":") || /\s/.test(host)) return null;
  // Basic host shape: must not be empty; full IPv4 validity is enforced
  // by isAllowedHost at the relay layer. Still reject obviously broken
  // values such as "."-only or empty labels here is not required, so
  // keep parseDst permissive on host content beyond non-emptiness.
  let port = DEFAULT_PORT;
  if (parts.length === 2) {
    if (portRaw === "") return null;
    if (!PORT_RE.test(portRaw)) return null;
    // Reject leading "+"/"-" (already excluded by regex) and octal tricks:
    // Number() on a digit-only string is safe here.
    port = Number(portRaw);
    if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) return null;
  }
  return { host, port };
}
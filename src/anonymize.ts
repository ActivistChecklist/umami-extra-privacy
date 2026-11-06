import { createHmac, randomBytes } from 'node:crypto';
import { isIPv4 as netIsIPv4, isIPv6 as netIsIPv6 } from 'node:net';

export type AnonymizationLevel =
  | 'none'
  | 'mask24'
  | 'mask16'
  | 'geo-hash'
  | 'hash'
  | 'drop';

/** How long one random key lasts before it is thrown away. */
export type SaltRotation = 'daily' | 'hourly' | 'none';

export interface AnonymizeOptions {
  level: AnonymizationLevel;
  rotation?: SaltRotation;
  now?: () => Date;
}

// How much of the real address `geo-hash` keeps, so a GeoLite2 lookup on the
// stand-in still lands near the visitor. The bits after these are shuffled
// with the period's key. For IPv6 only bits 28-63 are shuffled and the
// interface ID (bits 64-127) is zeroed.
const GEO_KEEP_V4 = 19;
const GEO_KEEP_V6 = 28;

// ---------- keys ----------

interface PeriodKey {
  period: string;
  key: Buffer;
  timer?: ReturnType<typeof setTimeout>;
}

// One random key per rotation mode. Keys exist only in this process's memory:
// they are never derived from a secret, written anywhere or logged. When a
// period ends its key is wiped, so nobody (us included) can recompute that
// period's stand-ins from a real address. A restart also starts a new key, so
// a visitor who is active across a restart shows up as two sessions that day.
const keys = new Map<SaltRotation, PeriodKey>();

function periodOf(rotation: SaltRotation, now: Date): string {
  if (rotation === 'none') return '';
  const iso = now.toISOString();
  return rotation === 'hourly' ? iso.slice(0, 13) : iso.slice(0, 10);
}

function msUntilNextPeriod(rotation: SaltRotation, now: Date): number | null {
  if (rotation === 'none') return null;
  const next = new Date(now.getTime());
  if (rotation === 'hourly') {
    next.setUTCMinutes(60, 0, 0);
  } else {
    next.setUTCHours(24, 0, 0, 0);
  }
  return next.getTime() - now.getTime();
}

function discardKey(rotation: SaltRotation): void {
  const entry = keys.get(rotation);
  if (!entry) return;
  if (entry.timer) clearTimeout(entry.timer);
  entry.key.fill(0);
  keys.delete(rotation);
}

function keyFor(rotation: SaltRotation, now: Date): Buffer {
  const period = periodOf(rotation, now);
  const current = keys.get(rotation);
  if (current && current.period === period) return current.key;
  discardKey(rotation);

  const entry: PeriodKey = { period, key: randomBytes(32) };
  const msLeft = msUntilNextPeriod(rotation, now);
  if (msLeft !== null) {
    // Wipe the key when its period ends even if no request arrives to replace
    // it. unref() so the timer never keeps the process alive.
    entry.timer = setTimeout(() => {
      if (keys.get(rotation) === entry) discardKey(rotation);
    }, msLeft);
    entry.timer.unref?.();
  }
  keys.set(rotation, entry);
  return entry.key;
}

// ---------- parsing ----------

interface ParsedIp {
  version: 4 | 6;
  value: bigint;
}

function ipv4ToBigInt(ip: string): bigint {
  return ip
    .split('.')
    .reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
}

function ipv6ToBigInt(ip: string): bigint | null {
  if (!netIsIPv6(ip)) return null;
  let text = ip;
  // A dotted IPv4 tail (::ffff:1.2.3.4) becomes the last two hex groups.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToBigInt(tail);
    text =
      text.slice(0, lastColon + 1) +
      (v4 >> 16n).toString(16) +
      ':' +
      (v4 & 0xffffn).toString(16);
  }
  const halves = text.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const groups = [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

/**
 * Parse an address the way proxies hand it over: plain IPv4 or IPv6, an IPv6
 * zone ID, `[v6]` or `[v6]:port`, or `v4:port`. IPv4-mapped IPv6
 * (`::ffff:1.2.3.4`) is an IPv4 visitor, so it comes back as IPv4. Anything
 * else is null, so it never reaches Umami unchanged.
 */
function parseIp(raw: string): ParsedIp | null {
  let text = raw;
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
  if (bracketed) {
    text = bracketed[1]!;
  } else {
    const withPort = /^([\d.]+):\d{1,5}$/.exec(text);
    if (withPort) text = withPort[1]!;
  }
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);

  if (netIsIPv4(text)) return { version: 4, value: ipv4ToBigInt(text) };
  const v6 = ipv6ToBigInt(text);
  if (v6 === null) return null;
  if (v6 >> 32n === 0xffffn) return { version: 4, value: v6 & 0xffffffffn };
  return { version: 6, value: v6 };
}

function formatIp({ version, value }: ParsedIp): string {
  const count = version === 4 ? 4 : 8;
  const size = version === 4 ? 8n : 16n;
  const mask = (1n << size) - 1n;
  const parts: string[] = [];
  for (let i = count - 1; i >= 0; i--) {
    const part = (value >> (BigInt(i) * size)) & mask;
    parts.push(version === 4 ? part.toString(10) : part.toString(16));
  }
  return parts.join(version === 4 ? '.' : ':');
}

// ---------- levels ----------

function widthOf(version: 4 | 6): number {
  return version === 4 ? 32 : 128;
}

function keepLeadingBits(ip: ParsedIp, keep: number): string {
  const drop = BigInt(widthOf(ip.version) - keep);
  return formatIp({ version: ip.version, value: (ip.value >> drop) << drop });
}

/**
 * Keyed permutation of `bits`-bit integers (a small Feistel network). Every
 * input maps to a different output, so distinct visitors in one block keep
 * distinct stand-ins. `tweak` gives each block its own shuffle.
 */
function shuffle(key: Buffer, tweak: string, value: bigint, bits: number): bigint {
  let a = Math.floor(bits / 2);
  let b = bits - a;
  let left = value >> BigInt(b);
  let right = value & ((1n << BigInt(b)) - 1n);
  for (let round = 0; round < 4; round++) {
    const digest = createHmac('sha256', key)
      .update(`${tweak}/${round}/${right}`)
      .digest();
    const f = digest.readBigUInt64BE(0);
    [left, right] = [right, (left ^ f) & ((1n << BigInt(a)) - 1n)];
    [a, b] = [b, a];
  }
  return (left << BigInt(b)) | right;
}

function geoHash(ip: ParsedIp, key: Buffer): string {
  const width = widthOf(ip.version);
  const keep = ip.version === 4 ? GEO_KEEP_V4 : GEO_KEEP_V6;
  const shuffled = (ip.version === 4 ? 32 : 64) - keep;
  const zeroed = BigInt(width - keep - shuffled);
  const block = ip.value >> BigInt(width - keep);
  const middle = (ip.value >> zeroed) & ((1n << BigInt(shuffled)) - 1n);
  const mixed = shuffle(key, `${ip.version}:${block}`, middle, shuffled);
  return formatIp({
    version: ip.version,
    value: (block << BigInt(width - keep)) | (mixed << zeroed),
  });
}

/**
 * Anonymize an IP address according to the given level.
 *
 * - `none`: returns the input unchanged
 * - `drop`: returns null (caller should omit the IP)
 * - `mask24`: zeroes the last octet (IPv4) or last 5 groups (IPv6 /48)
 * - `mask16`: zeroes the last two octets (IPv4) or last 4 groups (IPv6 /64)
 * - `hash`: returns an opaque hash (no geo info)
 * - `geo-hash`: keeps the first 19 bits of IPv4 or 28 bits of IPv6 for a
 *   rough location and shuffles the rest into a stand-in address
 *
 * The hashing levels (`hash`, `geo-hash`) use a random key that lives only in
 * memory and is replaced every `rotation` period (default `daily`, in UTC).
 * The same address gives the same result within a period, so analytics
 * sessions still work. Once the period's key is gone, no one can map its
 * results back to a real address.
 *
 * Every level except `none` returns null for input that is not an IP address.
 */
export function anonymizeIp(
  ip: string | null | undefined,
  options: AnonymizeOptions
): string | null {
  if (!ip) return null;
  const trimmed = ip.trim();
  if (!trimmed) return null;

  const { level } = options;
  if (level === 'drop') return null;
  if (level === 'none') return trimmed;

  const parsed = parseIp(trimmed);
  if (!parsed) return null;

  if (level === 'mask24') {
    return keepLeadingBits(parsed, parsed.version === 4 ? 24 : 48);
  }
  if (level === 'mask16') {
    return keepLeadingBits(parsed, parsed.version === 4 ? 16 : 64);
  }

  const rotation = options.rotation ?? 'daily';
  const now = (options.now ?? (() => new Date()))();
  const key = keyFor(rotation, now);

  if (level === 'hash') {
    return createHmac('sha256', key).update(formatIp(parsed)).digest('hex');
  }
  return geoHash(parsed, key);
}

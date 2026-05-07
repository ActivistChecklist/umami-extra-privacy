import { createHash } from 'node:crypto';

export type AnonymizationLevel =
  | 'none'
  | 'mask24'
  | 'mask16'
  | 'geo-hash'
  | 'hash'
  | 'drop';

export type SaltRotation = 'daily' | 'hourly' | 'none';

export interface AnonymizeOptions {
  level: AnonymizationLevel;
  salt?: string;
  rotation?: SaltRotation;
  now?: () => Date;
}

function rotationKey(rotation: SaltRotation, now: Date): string {
  if (rotation === 'none') return '';
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  if (rotation === 'hourly') {
    const h = String(now.getUTCHours()).padStart(2, '0');
    return `${y}-${m}-${d}T${h}`;
  }
  return `${y}-${m}-${d}`;
}

function hashIp(ip: string, salt: string, rotationSalt: string): string {
  return createHash('sha256').update(ip + rotationSalt + salt).digest('hex');
}

function isIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function isIPv6(ip: string): boolean {
  return ip.includes(':');
}

function stripIPv6Zone(ip: string): string {
  const idx = ip.indexOf('%');
  return idx === -1 ? ip : ip.slice(0, idx);
}

function expandIPv6(ip: string): string[] | null {
  const cleaned = stripIPv6Zone(ip);
  if (cleaned.includes('.')) {
    return null;
  }
  const parts = cleaned.split('::');
  if (parts.length > 2) return null;

  let head: string[] = [];
  let tail: string[] = [];

  if (parts.length === 1) {
    head = parts[0]!.split(':');
  } else {
    head = parts[0] === '' ? [] : parts[0]!.split(':');
    tail = parts[1] === '' ? [] : parts[1]!.split(':');
  }

  const total = head.length + tail.length;
  if (total > 8) return null;
  if (parts.length === 1 && total !== 8) return null;

  const fillCount = 8 - total;
  const groups = [...head, ...Array(fillCount).fill('0'), ...tail];

  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
  }
  return groups.map((g) => g.toLowerCase().padStart(4, '0'));
}

function maskIPv4(ip: string, keepOctets: 2 | 3): string | null {
  if (!isIPv4(ip)) return null;
  const parts = ip.split('.');
  if (keepOctets === 3) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  return `${parts[0]}.${parts[1]}.0.0`;
}

function maskIPv6(ip: string, keepGroups: 3 | 4): string | null {
  const groups = expandIPv6(ip);
  if (!groups) return null;
  const kept = groups.slice(0, keepGroups);
  const zeroed = Array(8 - keepGroups).fill('0');
  return [...kept, ...zeroed].map((g) => g.replace(/^0+(?=.)/, '')).join(':');
}

function geoHashIPv4(ip: string, salt: string, rotationSalt: string): string {
  const parts = ip.split('.');
  const userHash = hashIp(ip, salt, rotationSalt);
  const thirdInt = Number(parts[2]);
  const thirdHigh = thirdInt & 0xe0;
  const thirdRandom = parseInt(userHash.slice(0, 2), 16) & 0x1f;
  const anonThird = thirdHigh | thirdRandom;
  const anonFourth = parseInt(userHash.slice(2, 6), 16) % 256;
  return `${parts[0]}.${parts[1]}.${anonThird}.${anonFourth}`;
}

function geoHashIPv6(ip: string, salt: string, rotationSalt: string): string {
  const groups = expandIPv6(ip);
  if (!groups) return ip;
  const userHash = hashIp(ip, salt, rotationSalt);
  const kept = groups.slice(0, 3);
  const fourth = userHash.slice(0, 4);
  return [...kept, fourth, '0', '0', '0', '0']
    .map((g) => g.replace(/^0+(?=.)/, ''))
    .join(':');
}

/**
 * Anonymize an IP address according to the given level.
 *
 * - `none`: returns the input unchanged
 * - `drop`: returns null (caller should omit the IP)
 * - `mask24`: zeroes the last octet (IPv4) or last 5 groups (IPv6 /48)
 * - `mask16`: zeroes the last two octets (IPv4) or last 4 groups (IPv6 /64)
 * - `hash`: returns an opaque rotating hash (no geo info)
 * - `geo-hash`: keeps coarse geo info, randomizes the rest with a rotating salt
 *
 * For hashing levels (`hash`, `geo-hash`), `salt` is required. Rotation defaults
 * to `daily` so the same IP maps to a different hash each day.
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

  const v4 = isIPv4(trimmed);
  const v6 = !v4 && isIPv6(trimmed);
  if (!v4 && !v6) return trimmed;

  if (level === 'mask24') {
    return v4 ? maskIPv4(trimmed, 3) : maskIPv6(trimmed, 3);
  }
  if (level === 'mask16') {
    return v4 ? maskIPv4(trimmed, 2) : maskIPv6(trimmed, 4);
  }

  const salt = options.salt;
  if (!salt) {
    throw new Error(
      `anonymizeIp: level "${level}" requires a non-empty salt. ` +
        'Set IP_HASH_SALT in the environment or pass salt in config.'
    );
  }

  const rotation = options.rotation ?? 'daily';
  const now = (options.now ?? (() => new Date()))();
  const rotationSalt = rotationKey(rotation, now);

  if (level === 'hash') {
    return hashIp(trimmed, salt, rotationSalt);
  }
  return v4
    ? geoHashIPv4(trimmed, salt, rotationSalt)
    : geoHashIPv6(trimmed, salt, rotationSalt);
}

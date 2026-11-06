import { createHash, randomBytes } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import { anonymizeIp } from '../src/anonymize.js';

const FIXED_DATE = new Date('2026-05-07T12:00:00Z');
const fixedNow = () => FIXED_DATE;
const at = (iso: string) => () => new Date(iso);

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
}

/** First `bits` bits of two IPv4 addresses match. */
function sameV4Block(a: string, b: string, bits: number): boolean {
  const shift = 2 ** (32 - bits);
  return Math.floor(ipv4ToInt(a) / shift) === Math.floor(ipv4ToInt(b) / shift);
}

/** A new copy of the module, as after a process restart. */
async function restartedModule() {
  vi.resetModules();
  return import('../src/anonymize.js');
}

describe('anonymizeIp', () => {
  describe('null/empty input', () => {
    it('returns null for null', () => {
      expect(anonymizeIp(null, { level: 'none' })).toBeNull();
    });
    it('returns null for undefined', () => {
      expect(anonymizeIp(undefined, { level: 'geo-hash' })).toBeNull();
    });
    it('returns null for empty string', () => {
      expect(anonymizeIp('', { level: 'mask24' })).toBeNull();
    });
    it('returns null for whitespace', () => {
      expect(anonymizeIp('   ', { level: 'mask24' })).toBeNull();
    });
  });

  describe('level=none', () => {
    it('returns IP unchanged', () => {
      expect(anonymizeIp('203.0.113.42', { level: 'none' })).toBe('203.0.113.42');
    });
    it('trims whitespace', () => {
      expect(anonymizeIp('  203.0.113.42  ', { level: 'none' })).toBe('203.0.113.42');
    });
  });

  describe('level=drop', () => {
    it('returns null', () => {
      expect(anonymizeIp('203.0.113.42', { level: 'drop' })).toBeNull();
    });
  });

  describe('level=mask24 (IPv4)', () => {
    it('zeroes the last octet', () => {
      expect(anonymizeIp('203.0.113.42', { level: 'mask24' })).toBe('203.0.113.0');
    });
    it('handles edge octets', () => {
      expect(anonymizeIp('1.2.3.255', { level: 'mask24' })).toBe('1.2.3.0');
    });
  });

  describe('level=mask16 (IPv4)', () => {
    it('zeroes the last two octets', () => {
      expect(anonymizeIp('203.0.113.42', { level: 'mask16' })).toBe('203.0.0.0');
    });
  });

  describe('level=hash', () => {
    it('produces a 64-char hex hash without any salt configured', () => {
      const out = anonymizeIp('203.0.113.42', { level: 'hash', now: fixedNow });
      expect(out).toMatch(/^[0-9a-f]{64}$/);
    });
    it('gives different addresses different hashes', () => {
      const a = anonymizeIp('203.0.113.42', { level: 'hash', now: fixedNow });
      const b = anonymizeIp('203.0.113.43', { level: 'hash', now: fixedNow });
      expect(a).not.toBe(b);
    });
    it('does not rotate within the same day', () => {
      const morning = anonymizeIp('203.0.113.42', {
        level: 'hash',
        now: at('2026-05-07T01:00:00Z'),
      });
      const evening = anonymizeIp('203.0.113.42', {
        level: 'hash',
        now: at('2026-05-07T23:00:00Z'),
      });
      expect(morning).toBe(evening);
    });
    it('changes day-over-day with daily rotation', () => {
      const day1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        now: at('2026-05-07T12:00:00Z'),
      });
      const day2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        now: at('2026-05-08T12:00:00Z'),
      });
      expect(day1).not.toBe(day2);
    });
    it('rotates hourly when rotation=hourly', () => {
      const h1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        rotation: 'hourly',
        now: at('2026-05-07T01:00:00Z'),
      });
      const h2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        rotation: 'hourly',
        now: at('2026-05-07T02:00:00Z'),
      });
      expect(h1).not.toBe(h2);
    });
    it('keeps one key for the life of the process when rotation=none', () => {
      const day1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        rotation: 'none',
        now: at('2026-05-07T12:00:00Z'),
      });
      const day2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        rotation: 'none',
        now: at('2030-12-31T12:00:00Z'),
      });
      expect(day1).toBe(day2);
    });
  });

  describe('level=geo-hash (IPv4)', () => {
    it('keeps the first 19 bits and stays a valid IPv4 address', () => {
      const out = anonymizeIp('203.0.113.42', { level: 'geo-hash', now: fixedNow })!;
      const parts = out.split('.');
      expect(parts).toHaveLength(4);
      for (const p of parts) {
        expect(Number(p)).toBeGreaterThanOrEqual(0);
        expect(Number(p)).toBeLessThanOrEqual(255);
      }
      expect(sameV4Block(out, '203.0.113.42', 19)).toBe(true);
    });
    it('gives the same address the same stand-in all day', () => {
      const morning = anonymizeIp('1.2.3.4', {
        level: 'geo-hash',
        now: at('2026-05-07T00:00:01Z'),
      });
      const evening = anonymizeIp('1.2.3.4', {
        level: 'geo-hash',
        now: at('2026-05-07T23:59:59Z'),
      });
      expect(morning).toBe(evening);
    });
    it('gives every address in a /19 its own stand-in inside that /19', () => {
      const seen = new Set<string>();
      for (let i = 0; i < 8192; i++) {
        const ip = `198.51.${96 + (i >> 8)}.${i & 255}`;
        const out = anonymizeIp(ip, { level: 'geo-hash', now: fixedNow })!;
        expect(sameV4Block(out, '198.51.96.0', 19)).toBe(true);
        seen.add(out);
      }
      expect(seen.size).toBe(8192);
    });
    it('gives the same addresses new stand-ins the next day', () => {
      let changed = 0;
      for (let i = 0; i < 20; i++) {
        const ip = `203.0.113.${i}`;
        const day1 = anonymizeIp(ip, { level: 'geo-hash', now: at('2026-05-07T12:00:00Z') });
        const day2 = anonymizeIp(ip, { level: 'geo-hash', now: at('2026-05-08T12:00:00Z') });
        if (day1 !== day2) changed++;
      }
      // A stand-in repeats by chance 1 time in 8,192.
      expect(changed).toBeGreaterThan(15);
    });
  });

  describe('level=geo-hash (IPv6)', () => {
    const v6 = '2001:db8:1234:5678:9abc:def0:1234:5678';
    it('keeps the first 28 bits and zeroes the interface ID', () => {
      const groups = anonymizeIp(v6, { level: 'geo-hash', now: fixedNow })!.split(':');
      expect(groups).toHaveLength(8);
      expect(groups[0]).toBe('2001');
      expect(parseInt(groups[1]!, 16) >> 4).toBe(0xdb8 >> 4);
      expect(groups.slice(4)).toEqual(['0', '0', '0', '0']);
    });
    it('gives the same address the same stand-in all day', () => {
      const morning = anonymizeIp(v6, { level: 'geo-hash', now: at('2026-05-07T00:00:01Z') });
      const evening = anonymizeIp(v6, { level: 'geo-hash', now: at('2026-05-07T23:59:59Z') });
      expect(morning).toBe(evening);
    });
    it('gives one household one stand-in, whatever its interface ID', () => {
      const a = anonymizeIp('2001:db8:1234:5678::1', { level: 'geo-hash', now: fixedNow });
      const b = anonymizeIp('2001:db8:1234:5678::2', { level: 'geo-hash', now: fixedNow });
      expect(a).toBe(b);
    });
  });

  describe('IPv6 masks', () => {
    const v6 = '2001:db8:1234:5678:9abc:def0:1234:5678';
    it('mask24 zeroes the last 5 groups', () => {
      expect(anonymizeIp(v6, { level: 'mask24' })).toBe('2001:db8:1234:0:0:0:0:0');
    });
    it('mask16 zeroes the last 4 groups', () => {
      expect(anonymizeIp(v6, { level: 'mask16' })).toBe('2001:db8:1234:5678:0:0:0:0');
    });
    it('handles compressed :: notation', () => {
      expect(anonymizeIp('2001:db8::1', { level: 'mask16' })).toBe('2001:db8:0:0:0:0:0:0');
    });
    it('strips zone identifier', () => {
      expect(anonymizeIp('fe80::1%eth0', { level: 'mask16' })).toBe('fe80:0:0:0:0:0:0:0');
    });
    it('hash produces a hex hash', () => {
      expect(anonymizeIp(v6, { level: 'hash', now: fixedNow })).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('address formats proxies send', () => {
    it('treats IPv4-mapped IPv6 as the IPv4 address it wraps', () => {
      expect(anonymizeIp('::ffff:203.0.113.42', { level: 'mask24' })).toBe('203.0.113.0');
      expect(anonymizeIp('::ffff:cb00:712a', { level: 'mask24' })).toBe('203.0.113.0');
      const out = anonymizeIp('::ffff:203.0.113.42', { level: 'geo-hash', now: fixedNow })!;
      expect(out).toBe(anonymizeIp('203.0.113.42', { level: 'geo-hash', now: fixedNow }));
    });
    it('strips a port', () => {
      expect(anonymizeIp('203.0.113.42:443', { level: 'mask24' })).toBe('203.0.113.0');
      expect(anonymizeIp('[2001:db8::1]:443', { level: 'mask16' })).toBe('2001:db8:0:0:0:0:0:0');
      expect(anonymizeIp('[2001:db8::1]', { level: 'mask16' })).toBe('2001:db8:0:0:0:0:0:0');
    });
    it('returns null for anything that is not an IP address', () => {
      const junk = ['not-an-ip', '256.0.0.1', '01.2.3.4', '1.2.3', '1.2.3.4, 5.6.7.8', '1:2:3'];
      for (const raw of junk) {
        for (const level of ['mask24', 'mask16', 'geo-hash', 'hash'] as const) {
          expect(anonymizeIp(raw, { level, now: fixedNow }), `${level} ${raw}`).toBeNull();
        }
      }
    });
    it('still passes junk through unchanged at level=none', () => {
      expect(anonymizeIp('not-an-ip', { level: 'none' })).toBe('not-an-ip');
    });
  });
});

describe('how much geo-hash trims', () => {
  // For each bit position (0 = leftmost), the share of addresses whose
  // stand-in differs from the real address at that bit. A kept bit never
  // differs. A trimmed bit is replaced with a key-dependent bit, so it differs
  // about half the time, like a coin flip.
  function flipRates(pairs: [bigint, bigint][], width: number): number[] {
    const rates: number[] = [];
    for (let bit = 0; bit < width; bit++) {
      const shift = BigInt(width - 1 - bit);
      const flips = pairs.filter(([real, out]) => ((real ^ out) >> shift) & 1n).length;
      rates.push(flips / pairs.length);
    }
    return rates;
  }
  const toBigInt = (parts: string[], size: bigint, radix: number) =>
    parts.reduce((acc, p) => (acc << size) | BigInt(parseInt(p, radix)), 0n);
  const SAMPLES = 4000;

  it('IPv4: keeps bits 0-18 and replaces every one of bits 19-31', () => {
    const pairs: [bigint, bigint][] = [];
    for (let i = 0; i < SAMPLES; i++) {
      const ip = [...randomBytes(4)].join('.');
      const out = anonymizeIp(ip, { level: 'geo-hash', now: fixedNow })!;
      pairs.push([toBigInt(ip.split('.'), 8n, 10), toBigInt(out.split('.'), 8n, 10)]);
    }
    const rates = flipRates(pairs, 32);
    expect(rates.slice(0, 19)).toEqual(Array(19).fill(0));
    for (const rate of rates.slice(19)) {
      expect(rate).toBeGreaterThan(0.4);
      expect(rate).toBeLessThan(0.6);
    }
  });

  it('IPv6: keeps bits 0-27, replaces every one of bits 28-63 and zeroes bits 64-127', () => {
    const pairs: [bigint, bigint][] = [];
    for (let i = 0; i < SAMPLES; i++) {
      const groups = randomBytes(16).toString('hex').match(/.{4}/g)!;
      const out = anonymizeIp(groups.join(':'), { level: 'geo-hash', now: fixedNow })!;
      const outValue = toBigInt(out.split(':'), 16n, 16);
      expect(outValue & ((1n << 64n) - 1n)).toBe(0n);
      pairs.push([toBigInt(groups, 16n, 16), outValue]);
    }
    const rates = flipRates(pairs, 64 + 64).slice(0, 64);
    expect(rates.slice(0, 28)).toEqual(Array(28).fill(0));
    for (const rate of rates.slice(28)) {
      expect(rate).toBeGreaterThan(0.4);
      expect(rate).toBeLessThan(0.6);
    }
  });
});

describe('daily key', () => {
  it('cannot be recomputed after a restart, even for the same address and day', async () => {
    const before = await restartedModule();
    const after = await restartedModule();
    const opts = { level: 'hash', now: fixedNow } as const;
    expect(before.anonymizeIp('203.0.113.42', opts)).toBe(
      before.anonymizeIp('203.0.113.42', opts)
    );
    expect(after.anonymizeIp('203.0.113.42', opts)).not.toBe(
      before.anonymizeIp('203.0.113.42', opts)
    );
  });

  it('does not come back when an earlier day is asked for again', () => {
    const opts = (iso: string) => ({ level: 'hash', now: at(iso) }) as const;
    const first = anonymizeIp('203.0.113.42', opts('2026-06-01T12:00:00Z'));
    anonymizeIp('203.0.113.42', opts('2026-06-02T12:00:00Z'));
    const again = anonymizeIp('203.0.113.42', opts('2026-06-01T12:00:00Z'));
    expect(again).not.toBe(first);
  });

  it('is thrown away at midnight UTC even if no request comes in', async () => {
    vi.useFakeTimers();
    try {
      const { anonymizeIp: fresh } = await restartedModule();
      const opts = { level: 'hash', now: at('2026-05-07T23:59:59.000Z') } as const;
      const before = fresh('203.0.113.42', opts);
      vi.advanceTimersByTime(999);
      expect(fresh('203.0.113.42', opts)).toBe(before);
      vi.advanceTimersByTime(1);
      // The key is gone, so even the same moment gets a new one.
      expect(fresh('203.0.113.42', opts)).not.toBe(before);
    } finally {
      vi.useRealTimers();
    }
  });

  it('defeats the old brute force that used the static IP_HASH_SALT', () => {
    // The previous version filled the hidden 13 bits from
    // sha256(ip + 'YYYY-MM-DD' + IP_HASH_SALT). Anyone holding the salt could
    // run that over all 8,192 addresses in the /19 and keep the ones that
    // match the stored stand-in. The real address is on that list exactly
    // when the old formula, run on it, gives the stored value.
    const salt = 'the-old-static-salt';
    const oldGeoHash = (ip: string) => {
      const p = ip.split('.');
      const h = createHash('sha256').update(ip + '2026-05-07' + salt).digest('hex');
      const third = (Number(p[2]) & 0xe0) | (parseInt(h.slice(0, 2), 16) & 0x1f);
      const fourth = parseInt(h.slice(2, 6), 16) % 256;
      return `${p[0]}.${p[1]}.${third}.${fourth}`;
    };

    let recovered = 0;
    for (let i = 0; i < 200; i++) {
      const ip = `${11 + i}.${(i * 37) % 256}.${(i * 91) % 256}.${(i * 53) % 256}`;
      const stored = anonymizeIp(ip, { level: 'geo-hash', now: fixedNow });
      if (oldGeoHash(ip) === stored) recovered++;
    }
    // Against the old scheme this is 200. Now the real address matches only
    // by chance, about 1 time in 8,192.
    expect(recovered).toBeLessThanOrEqual(2);
  });
});

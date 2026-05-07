import { describe, it, expect } from 'vitest';
import { anonymizeIp } from '../src/anonymize.js';

const FIXED_DATE = new Date('2026-05-07T12:00:00Z');
const fixedNow = () => FIXED_DATE;

describe('anonymizeIp', () => {
  describe('null/empty input', () => {
    it('returns null for null', () => {
      expect(anonymizeIp(null, { level: 'none' })).toBeNull();
    });
    it('returns null for undefined', () => {
      expect(anonymizeIp(undefined, { level: 'geo-hash', salt: 'x' })).toBeNull();
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
    it('produces a 64-char hex hash', () => {
      const out = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 'pepper',
        now: fixedNow,
      });
      expect(out).toMatch(/^[0-9a-f]{64}$/);
    });
    it('is deterministic for the same IP/day/salt', () => {
      const a = anonymizeIp('203.0.113.42', { level: 'hash', salt: 's', now: fixedNow });
      const b = anonymizeIp('203.0.113.42', { level: 'hash', salt: 's', now: fixedNow });
      expect(a).toBe(b);
    });
    it('changes when salt changes', () => {
      const a = anonymizeIp('203.0.113.42', { level: 'hash', salt: 'a', now: fixedNow });
      const b = anonymizeIp('203.0.113.42', { level: 'hash', salt: 'b', now: fixedNow });
      expect(a).not.toBe(b);
    });
    it('changes day-over-day with daily rotation', () => {
      const day1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        now: () => new Date('2026-05-07T12:00:00Z'),
      });
      const day2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        now: () => new Date('2026-05-08T12:00:00Z'),
      });
      expect(day1).not.toBe(day2);
    });
    it('does not rotate within the same day', () => {
      const morning = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        now: () => new Date('2026-05-07T01:00:00Z'),
      });
      const evening = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        now: () => new Date('2026-05-07T23:00:00Z'),
      });
      expect(morning).toBe(evening);
    });
    it('rotates hourly when rotation=hourly', () => {
      const h1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        rotation: 'hourly',
        now: () => new Date('2026-05-07T01:00:00Z'),
      });
      const h2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        rotation: 'hourly',
        now: () => new Date('2026-05-07T02:00:00Z'),
      });
      expect(h1).not.toBe(h2);
    });
    it('does not rotate when rotation=none', () => {
      const day1 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        rotation: 'none',
        now: () => new Date('2026-05-07T12:00:00Z'),
      });
      const day2 = anonymizeIp('203.0.113.42', {
        level: 'hash',
        salt: 's',
        rotation: 'none',
        now: () => new Date('2030-12-31T12:00:00Z'),
      });
      expect(day1).toBe(day2);
    });
    it('throws when salt is missing', () => {
      expect(() => anonymizeIp('203.0.113.42', { level: 'hash' })).toThrow(/salt/i);
    });
    it('throws when salt is empty', () => {
      expect(() => anonymizeIp('203.0.113.42', { level: 'hash', salt: '' })).toThrow(/salt/i);
    });
  });

  describe('level=geo-hash (IPv4)', () => {
    it('preserves the first two octets', () => {
      const out = anonymizeIp('203.0.113.42', {
        level: 'geo-hash',
        salt: 's',
        now: fixedNow,
      });
      expect(out).toMatch(/^203\.0\./);
    });
    it('produces an IPv4-shaped output', () => {
      const out = anonymizeIp('8.8.8.8', {
        level: 'geo-hash',
        salt: 's',
        now: fixedNow,
      })!;
      const parts = out.split('.');
      expect(parts).toHaveLength(4);
      for (const p of parts) {
        const n = Number(p);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(255);
      }
    });
    it('keeps top 3 bits of the third octet', () => {
      const out = anonymizeIp('10.20.255.1', {
        level: 'geo-hash',
        salt: 's',
        now: fixedNow,
      })!;
      const third = Number(out.split('.')[2]);
      expect(third & 0xe0).toBe(255 & 0xe0);
    });
    it('is deterministic for same input/day', () => {
      const a = anonymizeIp('1.2.3.4', { level: 'geo-hash', salt: 's', now: fixedNow });
      const b = anonymizeIp('1.2.3.4', { level: 'geo-hash', salt: 's', now: fixedNow });
      expect(a).toBe(b);
    });
  });

  describe('IPv6', () => {
    const v6 = '2001:db8:1234:5678:9abc:def0:1234:5678';
    it('mask24 zeroes the last 5 groups', () => {
      const out = anonymizeIp(v6, { level: 'mask24' });
      expect(out).toBe('2001:db8:1234:0:0:0:0:0');
    });
    it('mask16 zeroes the last 4 groups', () => {
      const out = anonymizeIp(v6, { level: 'mask16' });
      expect(out).toBe('2001:db8:1234:5678:0:0:0:0');
    });
    it('handles compressed :: notation', () => {
      const out = anonymizeIp('2001:db8::1', { level: 'mask16' });
      expect(out).toBe('2001:db8:0:0:0:0:0:0');
    });
    it('strips zone identifier', () => {
      const out = anonymizeIp('fe80::1%eth0', { level: 'mask16' });
      expect(out).toBe('fe80:0:0:0:0:0:0:0');
    });
    it('hash produces a hex hash', () => {
      const out = anonymizeIp(v6, { level: 'hash', salt: 's', now: fixedNow });
      expect(out).toMatch(/^[0-9a-f]{64}$/);
    });
    it('geo-hash preserves first 3 groups', () => {
      const out = anonymizeIp(v6, { level: 'geo-hash', salt: 's', now: fixedNow })!;
      expect(out.startsWith('2001:db8:1234:')).toBe(true);
    });
  });

  describe('invalid IPs', () => {
    it('returns input unchanged for non-IP strings (with mask)', () => {
      expect(anonymizeIp('not-an-ip', { level: 'mask24' })).toBe('not-an-ip');
    });
    it('rejects octet > 255', () => {
      expect(anonymizeIp('256.0.0.1', { level: 'mask24' })).toBe('256.0.0.1');
    });
    it('rejects octet with leading zero', () => {
      expect(anonymizeIp('01.2.3.4', { level: 'mask24' })).toBe('01.2.3.4');
    });
  });
});

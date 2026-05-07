import { describe, it, expect } from 'vitest';
import {
  createCounterHandler,
  extractClientIp,
} from '../src/handler.js';
import type { UmamiConfig } from '../src/send.js';

const cloudConfig: UmamiConfig = {
  mode: 'cloud',
  apiKey: 'k',
  websiteId: 'w',
  endpoint: 'https://example.com',
};

function captureFetch() {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return new Response('ok', { status: 200 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

describe('createCounterHandler', () => {
  it('returns 500 when no Umami config is available', async () => {
    const handle = createCounterHandler({ env: {} });
    const result = await handle({
      ip: '1.2.3.4',
      body: { url: '/', hostname: 'h' },
    });
    expect(result.success).toBe(false);
    if (!result.success) expect(result.status).toBe(500);
  });

  it('returns 400 when body is missing', async () => {
    const handle = createCounterHandler({ config: cloudConfig });
    const result = await handle({ body: null });
    expect(result.success).toBe(false);
    if (!result.success) expect(result.status).toBe(400);
  });

  it('returns 400 when url is missing', async () => {
    const handle = createCounterHandler({ config: cloudConfig });
    const result = await handle({
      body: { hostname: 'h' },
    });
    if (!result.success) {
      expect(result.status).toBe(400);
      expect(result.error).toMatch(/url/i);
    } else {
      expect.fail('expected failure');
    }
  });

  it('returns 400 when hostname is missing and no host fallback', async () => {
    const handle = createCounterHandler({ config: cloudConfig });
    const result = await handle({ body: { url: '/' } });
    if (!result.success) {
      expect(result.status).toBe(400);
      expect(result.error).toMatch(/hostname/i);
    } else {
      expect.fail('expected failure');
    }
  });

  it('uses host header as fallback for hostname', async () => {
    const { fetchImpl, calls } = captureFetch();
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'mask24',
      fetchImpl,
    });
    const result = await handle({
      body: { url: '/' },
      host: 'fallback.example.com',
    });
    expect(result.success).toBe(true);
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.payload.hostname).toBe('fallback.example.com');
  });

  it('anonymizes the IP using the configured level', async () => {
    const { fetchImpl, calls } = captureFetch();
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'mask24',
      fetchImpl,
    });
    await handle({
      ip: '203.0.113.42',
      body: { url: '/', hostname: 'h' },
    });
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.payload.ip).toBe('203.0.113.0');
  });

  it('omits ip when level=drop', async () => {
    const { fetchImpl, calls } = captureFetch();
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'drop',
      fetchImpl,
    });
    await handle({
      ip: '203.0.113.42',
      body: { url: '/', hostname: 'h' },
    });
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.payload.ip).toBeUndefined();
  });

  it('reads salt from env (IP_HASH_SALT)', async () => {
    const { fetchImpl, calls } = captureFetch();
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'hash',
      env: { IP_HASH_SALT: 'env-salt' },
      fetchImpl,
    });
    const result = await handle({
      ip: '1.2.3.4',
      body: { url: '/', hostname: 'h' },
    });
    expect(result.success).toBe(true);
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.payload.ip).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns 500 when hashing level lacks salt', async () => {
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'hash',
      env: {},
    });
    const result = await handle({
      ip: '1.2.3.4',
      body: { url: '/', hostname: 'h' },
    });
    expect(result.success).toBe(false);
    if (!result.success) expect(result.status).toBe(500);
  });

  it('returns 502 when sendUmamiEvent fails', async () => {
    const fetchImpl = (async () =>
      new Response('boom', { status: 500 })) as unknown as typeof fetch;
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'mask24',
      fetchImpl,
    });
    const result = await handle({
      ip: '1.2.3.4',
      body: { url: '/', hostname: 'h' },
    });
    expect(result.success).toBe(false);
    if (!result.success) expect(result.status).toBe(502);
  });

  it('forwards body fields into the payload', async () => {
    const { fetchImpl, calls } = captureFetch();
    const handle = createCounterHandler({
      config: cloudConfig,
      level: 'drop',
      fetchImpl,
    });
    await handle({
      body: {
        url: '/page',
        hostname: 'h',
        referrer: '/prev',
        title: 'Hi',
        language: 'en',
        screen: '1024x768',
        name: 'click',
        data: { foo: 'bar' },
      },
      userAgent: 'UA',
    });
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.payload).toMatchObject({
      url: '/page',
      hostname: 'h',
      referrer: '/prev',
      title: 'Hi',
      language: 'en',
      screen: '1024x768',
      name: 'click',
      data: { foo: 'bar' },
    });
  });
});

describe('extractClientIp', () => {
  it('returns leftmost x-forwarded-for', () => {
    expect(
      extractClientIp({ 'x-forwarded-for': '1.1.1.1, 2.2.2.2' })
    ).toBe('1.1.1.1');
  });
  it('trims surrounding whitespace', () => {
    expect(
      extractClientIp({ 'x-forwarded-for': '  1.1.1.1  , 2.2.2.2' })
    ).toBe('1.1.1.1');
  });
  it('falls back to x-real-ip', () => {
    expect(extractClientIp({ 'x-real-ip': '3.3.3.3' })).toBe('3.3.3.3');
  });
  it('falls back to provided fallback', () => {
    expect(extractClientIp({}, '4.4.4.4')).toBe('4.4.4.4');
  });
  it('returns null when nothing is available', () => {
    expect(extractClientIp({})).toBeNull();
  });
  it('handles array headers', () => {
    expect(
      extractClientIp({ 'x-forwarded-for': ['1.1.1.1, 2.2.2.2'] })
    ).toBe('1.1.1.1');
  });
});

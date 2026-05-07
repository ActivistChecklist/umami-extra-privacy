import { describe, it, expect } from 'vitest';
import { resolveConfigFromEnv, sendUmamiEvent, type UmamiConfig } from '../src/send.js';

function makeMockFetch(response: { ok?: boolean; status?: number; statusText?: string; body?: string }) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return new Response(response.body ?? 'ok', {
      status: response.status ?? 200,
      statusText: response.statusText ?? 'OK',
    });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

describe('resolveConfigFromEnv', () => {
  it('returns null when nothing configured', () => {
    expect(resolveConfigFromEnv({})).toBeNull();
  });

  it('returns cloud config when API key + website ID present', () => {
    const cfg = resolveConfigFromEnv({
      UMAMI_API_KEY: 'k',
      UMAMI_WEBSITE_ID: 'w',
    });
    expect(cfg).toEqual({
      mode: 'cloud',
      apiKey: 'k',
      websiteId: 'w',
      endpoint: 'https://cloud.umami.is',
    });
  });

  it('honors UMAMI_API_CLIENT_ENDPOINT for cloud', () => {
    const cfg = resolveConfigFromEnv({
      UMAMI_API_KEY: 'k',
      UMAMI_WEBSITE_ID: 'w',
      UMAMI_API_CLIENT_ENDPOINT: 'https://example.com',
    });
    expect(cfg?.mode).toBe('cloud');
    expect((cfg as Extract<UmamiConfig, { mode: 'cloud' }>).endpoint).toBe('https://example.com');
  });

  it('returns self-hosted when full creds present', () => {
    const cfg = resolveConfigFromEnv({
      UMAMI_API_CLIENT_USER_ID: 'u',
      UMAMI_API_CLIENT_SECRET: 's',
      UMAMI_WEBSITE_ID: 'w',
      UMAMI_API_CLIENT_ENDPOINT: 'https://umami.example.com',
    });
    expect(cfg).toEqual({
      mode: 'self-hosted',
      userId: 'u',
      appSecret: 's',
      websiteId: 'w',
      endpoint: 'https://umami.example.com',
    });
  });

  it('uses UMAMI_HOST as a fallback for endpoint', () => {
    const cfg = resolveConfigFromEnv({
      UMAMI_API_CLIENT_USER_ID: 'u',
      UMAMI_API_CLIENT_SECRET: 's',
      UMAMI_WEBSITE_ID: 'w',
      UMAMI_HOST: 'https://umami.example.com',
    });
    expect(cfg?.mode).toBe('self-hosted');
  });

  it('prefers cloud over self-hosted when both are present', () => {
    const cfg = resolveConfigFromEnv({
      UMAMI_API_KEY: 'k',
      UMAMI_API_CLIENT_USER_ID: 'u',
      UMAMI_API_CLIENT_SECRET: 's',
      UMAMI_WEBSITE_ID: 'w',
      UMAMI_API_CLIENT_ENDPOINT: 'https://umami.example.com',
    });
    expect(cfg?.mode).toBe('cloud');
  });

  it('returns null for partial self-hosted config', () => {
    expect(
      resolveConfigFromEnv({
        UMAMI_API_CLIENT_USER_ID: 'u',
        UMAMI_API_CLIENT_SECRET: 's',
        UMAMI_WEBSITE_ID: 'w',
      })
    ).toBeNull();
  });
});

describe('sendUmamiEvent', () => {
  const cloudConfig: UmamiConfig = {
    mode: 'cloud',
    apiKey: 'cloud-key',
    websiteId: 'web-id',
    endpoint: 'https://cloud.example.com',
  };

  const selfConfig: UmamiConfig = {
    mode: 'self-hosted',
    userId: 'uid',
    appSecret: 'secret',
    websiteId: 'web-id',
    endpoint: 'https://self.example.com',
  };

  it('POSTs to <endpoint>/api/send', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://cloud.example.com/api/send');
    expect(calls[0]!.init.method).toBe('POST');
  });

  it('uses x-umami-api-key for cloud', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers['x-umami-api-key']).toBe('cloud-key');
    expect(headers['x-umami-hash']).toBeUndefined();
  });

  it('uses HMAC-style auth for self-hosted', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: selfConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers['x-umami-id']).toBe('uid');
    expect(headers['x-umami-hash']).toMatch(/^[0-9a-f]{64}$/);
    expect(headers['x-umami-timestamp']).toMatch(/^\d+$/);
    expect(headers['x-umami-api-key']).toBeUndefined();
  });

  it('injects website id into the payload', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/x', hostname: 'h' },
      fetchImpl,
    });
    const sent = JSON.parse(calls[0]!.init.body as string);
    expect(sent.type).toBe('event');
    expect(sent.payload.website).toBe('web-id');
    expect(sent.payload.url).toBe('/x');
  });

  it('forwards user agent', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      userAgent: 'TestUA/1.0',
      fetchImpl,
    });
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers['User-Agent']).toBe('TestUA/1.0');
  });

  it('returns success on 2xx', async () => {
    const { fetchImpl } = makeMockFetch({ status: 200, body: 'ok' });
    const res = await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(res).toEqual({ success: true, response: 'ok' });
  });

  it('returns failure on non-2xx', async () => {
    const { fetchImpl } = makeMockFetch({ status: 401, statusText: 'Unauthorized', body: 'bad key' });
    const res = await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.status).toBe(401);
      expect(res.error).toBe('bad key');
    }
  });

  it('returns failure on fetch throw', async () => {
    const fetchImpl = (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;
    const res = await sendUmamiEvent({
      config: cloudConfig,
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(res).toEqual({ success: false, error: 'network down' });
  });

  it('strips trailing slashes from the endpoint', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: { ...cloudConfig, endpoint: 'https://cloud.example.com//' },
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(calls[0]!.url).toBe('https://cloud.example.com/api/send');
  });

  it('adds https:// when missing', async () => {
    const { fetchImpl, calls } = makeMockFetch({});
    await sendUmamiEvent({
      config: { ...selfConfig, endpoint: 'self.example.com' },
      payload: { url: '/', hostname: 'h' },
      fetchImpl,
    });
    expect(calls[0]!.url).toBe('https://self.example.com/api/send');
  });
});

import { createHash } from 'node:crypto';

export interface UmamiCloudConfig {
  mode: 'cloud';
  apiKey: string;
  websiteId: string;
  endpoint?: string;
}

export interface UmamiSelfHostedConfig {
  mode: 'self-hosted';
  userId: string;
  appSecret: string;
  websiteId: string;
  endpoint: string;
}

export type UmamiConfig = UmamiCloudConfig | UmamiSelfHostedConfig;

export interface UmamiPayload {
  hostname?: string;
  url?: string;
  referrer?: string;
  title?: string;
  language?: string;
  screen?: string;
  name?: string;
  data?: Record<string, unknown>;
  ip?: string | null;
  [key: string]: unknown;
}

export interface SendOptions {
  config: UmamiConfig;
  payload: UmamiPayload;
  userAgent?: string;
  fetchImpl?: typeof fetch;
}

export type SendResult =
  | { success: true; response: string }
  | { success: false; error: string; status?: number };

const DEFAULT_CLOUD_ENDPOINT = 'https://cloud.umami.is';
const SEND_PATH = '/api/send';

function normalizeEndpoint(endpoint: string): string {
  let e = endpoint.trim();
  if (!e.startsWith('http://') && !e.startsWith('https://')) {
    e = 'https://' + e;
  }
  return e.replace(/\/+$/, '');
}

/**
 * Resolve a complete Umami config from environment variables.
 * Returns null if neither cloud nor self-hosted credentials are present.
 *
 * Cloud requires: UMAMI_API_KEY, UMAMI_WEBSITE_ID
 * Self-hosted requires: UMAMI_API_CLIENT_USER_ID, UMAMI_API_CLIENT_SECRET,
 *   UMAMI_WEBSITE_ID, UMAMI_API_CLIENT_ENDPOINT (or UMAMI_HOST)
 */
export function resolveConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env
): UmamiConfig | null {
  const websiteId = env.UMAMI_WEBSITE_ID;
  const endpoint = env.UMAMI_API_CLIENT_ENDPOINT || env.UMAMI_HOST;

  const apiKey = env.UMAMI_API_KEY;
  if (apiKey && websiteId) {
    return {
      mode: 'cloud',
      apiKey,
      websiteId,
      endpoint: endpoint || DEFAULT_CLOUD_ENDPOINT,
    };
  }

  const userId = env.UMAMI_API_CLIENT_USER_ID;
  const appSecret = env.UMAMI_API_CLIENT_SECRET;
  if (userId && appSecret && websiteId && endpoint) {
    return {
      mode: 'self-hosted',
      userId,
      appSecret,
      websiteId,
      endpoint,
    };
  }

  return null;
}

function buildAuthHeaders(config: UmamiConfig): Record<string, string> {
  if (config.mode === 'cloud') {
    return { 'x-umami-api-key': config.apiKey };
  }
  const timestamp = Date.now();
  const hash = createHash('sha256')
    .update(`${timestamp}:${config.userId}:${config.appSecret}`)
    .digest('hex');
  return {
    'x-umami-timestamp': String(timestamp),
    'x-umami-hash': hash,
    'x-umami-id': config.userId,
  };
}

/**
 * Send a single event to Umami. Framework-agnostic — the caller is responsible
 * for extracting/anonymizing IP and assembling the payload.
 */
export async function sendUmamiEvent(opts: SendOptions): Promise<SendResult> {
  const { config, payload, userAgent } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;

  const endpoint =
    config.mode === 'cloud'
      ? normalizeEndpoint(config.endpoint ?? DEFAULT_CLOUD_ENDPOINT)
      : normalizeEndpoint(config.endpoint);

  const url = endpoint + SEND_PATH;

  const fullPayload: UmamiPayload = {
    ...payload,
    website: config.websiteId,
  };

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': userAgent || 'Mozilla/5.0 (compatible; umami-extra-privacy)',
    ...buildAuthHeaders(config),
  };

  const body = JSON.stringify({ type: 'event', payload: fullPayload });

  try {
    const res = await fetchImpl(url, { method: 'POST', headers, body });
    const text = await res.text();
    if (res.ok) {
      return { success: true, response: text };
    }
    return {
      success: false,
      status: res.status,
      error: text || res.statusText || `HTTP ${res.status}`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

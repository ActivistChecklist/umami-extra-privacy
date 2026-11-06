import {
  anonymizeIp,
  type AnonymizationLevel,
  type SaltRotation,
} from './anonymize.js';
import {
  resolveConfigFromEnv,
  sendUmamiEvent,
  type SendResult,
  type UmamiConfig,
  type UmamiPayload,
} from './send.js';

export interface CounterHandlerOptions {
  /** Anonymization level applied to the client IP. Default: `geo-hash`. */
  level?: AnonymizationLevel;
  /**
   * How long each in-memory key for the hashing levels lasts before it is
   * thrown away. Default: `daily`.
   */
  rotation?: SaltRotation;
  /** Umami credentials. If omitted, resolved from `UMAMI_*` env vars. */
  config?: UmamiConfig;
  /** Override the env source (mostly for testing). */
  env?: NodeJS.ProcessEnv;
  /** Inject a fetch implementation (mostly for testing). */
  fetchImpl?: typeof fetch;
  /** Inject a clock (mostly for testing key rotation). */
  now?: () => Date;
}

export interface CounterHandlerInput {
  /** Raw client IP. The handler anonymizes before sending. */
  ip?: string | null;
  /** User-Agent header from the original request. */
  userAgent?: string;
  /** Parsed JSON body of the analytics request. */
  body: CounterRequestBody | null | undefined;
  /** Optional Host header fallback when body.hostname is empty. */
  host?: string;
  /** Optional Referer header fallback when body.referrer is empty. */
  referer?: string;
}

export interface CounterRequestBody {
  hostname?: string;
  url?: string;
  referrer?: string;
  title?: string;
  language?: string;
  screen?: string;
  userAgent?: string;
  name?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

export type CounterResult =
  | { success: true; status: 200; response: string }
  | { success: false; status: 400 | 500 | 502; error: string };

/**
 * Build a framework-agnostic request handler.
 *
 * Returns a function `(input) => Promise<CounterResult>` that:
 * 1. Validates the body has at least `hostname` and `url`.
 * 2. Anonymizes the IP per the configured level.
 * 3. Sends the event to Umami.
 *
 * Adapters (Fastify, Next.js, generic) wrap this to extract `ip`/`userAgent`/
 * `body` from their respective request shapes.
 */
export function createCounterHandler(options: CounterHandlerOptions = {}) {
  const level: AnonymizationLevel = options.level ?? 'geo-hash';
  const env = options.env ?? process.env;
  const rotation = options.rotation ?? 'daily';
  const config = options.config ?? resolveConfigFromEnv(env);

  return async function handle(
    input: CounterHandlerInput
  ): Promise<CounterResult> {
    if (!config) {
      return {
        success: false,
        status: 500,
        error:
          'Umami is not configured. Set UMAMI_API_KEY+UMAMI_WEBSITE_ID (cloud) or UMAMI_API_CLIENT_USER_ID+UMAMI_API_CLIENT_SECRET+UMAMI_WEBSITE_ID+UMAMI_API_CLIENT_ENDPOINT (self-hosted).',
      };
    }

    const body = input.body;
    if (!body || typeof body !== 'object') {
      return { success: false, status: 400, error: 'Missing request body.' };
    }

    const url = typeof body.url === 'string' ? body.url : '';
    const hostname =
      typeof body.hostname === 'string' && body.hostname
        ? body.hostname
        : input.host ?? '';

    if (!url) {
      return { success: false, status: 400, error: 'Missing required field: url.' };
    }
    if (!hostname) {
      return {
        success: false,
        status: 400,
        error: 'Missing required field: hostname.',
      };
    }

    const anonymizedIp = anonymizeIp(input.ip, {
      level,
      rotation,
      now: options.now,
    });

    const payload: UmamiPayload = {
      url,
      hostname,
      referrer:
        (typeof body.referrer === 'string' && body.referrer) ||
        input.referer ||
        '',
      title: typeof body.title === 'string' ? body.title : '',
      language: typeof body.language === 'string' ? body.language : '',
      screen: typeof body.screen === 'string' ? body.screen : '',
      name: typeof body.name === 'string' ? body.name : '',
      data: body.data,
    };
    if (anonymizedIp) {
      payload.ip = anonymizedIp;
    }

    const userAgent = input.userAgent ?? body.userAgent ?? '';

    const sendResult: SendResult = await sendUmamiEvent({
      config,
      payload,
      userAgent,
      fetchImpl: options.fetchImpl,
    });

    if (sendResult.success) {
      return { success: true, status: 200, response: sendResult.response };
    }
    return {
      success: false,
      status: 502,
      error: sendResult.error,
    };
  };
}

/**
 * Extract a client IP from common forwarding headers + a fallback. Returns the
 * leftmost IP in `x-forwarded-for`, or `x-real-ip`, or the fallback.
 */
export function extractClientIp(
  headers: Record<string, string | string[] | undefined>,
  fallback?: string | null
): string | null {
  const xff = headers['x-forwarded-for'];
  const xffStr = Array.isArray(xff) ? xff[0] : xff;
  if (xffStr) {
    const first = xffStr.split(',')[0]?.trim();
    if (first) return first;
  }
  const xri = headers['x-real-ip'];
  const xriStr = Array.isArray(xri) ? xri[0] : xri;
  if (xriStr && xriStr.trim()) return xriStr.trim();
  return fallback ?? null;
}

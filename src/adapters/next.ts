import {
  createCounterHandler,
  extractClientIp,
  type CounterHandlerOptions,
  type CounterRequestBody,
} from '../handler.js';

interface NextLikeRequest {
  headers: Headers;
  json(): Promise<unknown>;
}

/**
 * Build a Next.js App Router POST handler.
 *
 * Usage in `app/api/counter/route.ts`:
 *
 *   import { createRouteHandler } from '@activistchecklist/umami-extra-privacy/next';
 *   export const POST = createRouteHandler({ level: 'geo-hash' });
 *
 * Returns a `Response` directly. The consumer is responsible for any
 * additional middleware (rate limiting, CORS, etc.).
 */
export function createRouteHandler(options: CounterHandlerOptions = {}) {
  const handle = createCounterHandler(options);

  return async function POST(request: NextLikeRequest): Promise<Response> {
    let body: CounterRequestBody | null = null;
    try {
      body = (await request.json()) as CounterRequestBody;
    } catch {
      return jsonResponse(400, {
        success: false,
        error: 'Invalid JSON body.',
      });
    }

    const headersObj: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headersObj[key.toLowerCase()] = value;
    });

    const ip = extractClientIp(headersObj);
    const userAgent = headersObj['user-agent'] ?? '';
    const host = headersObj.host;
    const referer = headersObj.referer;

    const result = await handle({ ip, userAgent, body, host, referer });
    if (result.success) {
      return jsonResponse(200, { success: true });
    }
    return jsonResponse(result.status, {
      success: false,
      error: result.error,
    });
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export interface SendAnalyticsOptions {
  /** Endpoint to POST analytics events to. Default: `/api-server/counter`. */
  endpoint?: string;
  /**
   * Skip sending under any custom condition (e.g. dev mode). Default: send
   * always. Pass `() => process.env.NODE_ENV !== 'production'` to skip in dev.
   */
  skip?: () => boolean;
  /** AbortSignal forwarded to fetch. */
  signal?: AbortSignal;
}

export interface AnalyticsEventInput {
  url?: string;
  referrer?: string;
  hostname?: string;
  title?: string;
  userAgent?: string;
  screen?: string;
  language?: string;
  name?: string;
  data?: Record<string, unknown>;
}

const DEFAULT_ENDPOINT = '/api-server/counter';

/**
 * Browser-side helper that POSTs an analytics event to a server-side counter
 * endpoint. The server then anonymizes the IP and forwards to Umami.
 *
 * Auto-fills `url`, `referrer`, `hostname`, `title`, `userAgent`, and `screen`
 * from `window`/`document`/`navigator`. The caller can override any of these
 * or add `name`/`data` for custom events.
 *
 * Failures are swallowed silently (returns `null`) — analytics should never
 * break the page.
 */
export async function sendAnalytics(
  data: AnalyticsEventInput = {},
  options: SendAnalyticsOptions = {}
): Promise<Response | null> {
  if (typeof window === 'undefined') return null;
  if (options.skip && options.skip()) return null;

  const fullData: AnalyticsEventInput = {
    url: window.location.pathname,
    referrer: document.referrer,
    hostname: window.location.hostname,
    title: document.title,
    userAgent: navigator.userAgent,
    screen: `${window.screen.width}x${window.screen.height}`,
    language: navigator.language,
    ...data,
  };

  try {
    return await fetch(options.endpoint ?? DEFAULT_ENDPOINT, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
      },
      body: JSON.stringify(fullData),
      signal: options.signal,
    });
  } catch {
    return null;
  }
}

/** Run `callback` once the document has loaded. Returns a cleanup fn. */
export function initializeOnLoad(callback: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  if (document.readyState === 'complete') {
    callback();
    return () => {};
  }
  window.addEventListener('load', callback);
  return () => window.removeEventListener('load', callback);
}

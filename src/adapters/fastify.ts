import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import {
  createCounterHandler,
  extractClientIp,
  type CounterHandlerOptions,
  type CounterRequestBody,
} from '../handler.js';

export interface FastifyCounterOptions extends CounterHandlerOptions {
  /** Route path. Default: `/counter`. */
  route?: string;
  /**
   * Per-route `@fastify/rate-limit` config. Only applied if the consumer has
   * registered `@fastify/rate-limit` on the Fastify instance. The package does
   * not register the plugin for you.
   */
  rateLimit?: Record<string, unknown>;
}

const BODY_SCHEMA = {
  type: 'object',
  required: ['hostname', 'url'],
  properties: {
    hostname: { type: 'string' },
    url: { type: 'string' },
    referrer: { type: 'string' },
    title: { type: 'string' },
    language: { type: 'string' },
    screen: { type: 'string' },
    userAgent: { type: 'string' },
    name: { type: 'string' },
    data: { type: 'object' },
  },
  additionalProperties: true,
};

/**
 * Fastify plugin exposing a POST endpoint that relays anonymized analytics
 * events to Umami.
 *
 * Rate limiting, CORS, and security headers are intentionally left to the
 * consumer to wire up at the app level.
 */
export function createFastifyPlugin(
  options: FastifyCounterOptions = {}
): FastifyPluginAsync {
  const route = options.route ?? '/counter';
  const handle = createCounterHandler(options);

  return async function plugin(fastify: FastifyInstance) {
    const routeConfig: Record<string, unknown> = {};
    if (options.rateLimit) {
      routeConfig.rateLimit = options.rateLimit;
    }

    fastify.post(
      route,
      {
        config: routeConfig,
        schema: { body: BODY_SCHEMA },
      },
      async (request, reply) => {
        const headers = request.headers as Record<
          string,
          string | string[] | undefined
        >;
        const ip = extractClientIp(headers, request.ip);
        const userAgent =
          (typeof headers['user-agent'] === 'string'
            ? headers['user-agent']
            : Array.isArray(headers['user-agent'])
              ? headers['user-agent'][0]
              : undefined) ?? '';
        const host =
          typeof headers.host === 'string'
            ? headers.host
            : Array.isArray(headers.host)
              ? headers.host[0]
              : undefined;
        const referer =
          typeof headers.referer === 'string'
            ? headers.referer
            : Array.isArray(headers.referer)
              ? headers.referer[0]
              : undefined;

        const result = await handle({
          ip,
          userAgent,
          body: request.body as CounterRequestBody,
          host,
          referer,
        });

        if (result.success) {
          return reply.code(200).send({ success: true });
        }
        return reply.code(result.status).send({
          success: false,
          error: result.error,
        });
      }
    );
  };
}

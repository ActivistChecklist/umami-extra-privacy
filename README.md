# @activistchecklist/umami-extra-privacy

This packages adds a thin layer of additional privacy features on top of Umami [Umami](https://umami.is/) analytics.

* Sends Umami requests to a server-side API before sending them to the actual Umami instance. (Can be self-hosted or use Umami Cloud). This gives us control over what we send, and ensures that our user is never connecting to a server other than ours, for maximum privacy.
* (Optional) Trims off some data from the IP address so you can still get the user's approximate location without ever sending it to the server. (This is the `geo-hash` option.)

**Why does this matter?** If your Umami database is turned over to law enforcement, you now no longer have the exact IP addresses of your visitors. There is plausible deniability that any given person actually viewed your site.

**Doesn't Umami already obfuscate the IP addresses?** Yes, Umami generates a hash of IP addresses rather than storing the original. But if someone knows your APP_SECRET, the user agent, and the IP address, they can reverse engineer the hash and determine if a particular user was on your site. Using `hash` or `geo-hash`.

## What this package includes

* **6 anonymization levels** from `none` to `drop`, including a geo-preserving
  daily-rotating hash.
* **Cloud and self-hosted Umami** support — auto-detected from environment
  variables.
* **Adapters** for Fastify, Next.js App Router, and a generic
  `(input) => result` handler you can wire into anything.
* **Browser helper** that posts to your relay endpoint and silently swallows
  failures (analytics should never break the page).
* **No bundled middleware**: rate limiting, CORS, and security headers are
  intentionally left to your app.

## Install

This package is not published to npm. Use a Git dependency:

```jsonc
// package.json
{
  "dependencies": {
    "@activistchecklist/umami-extra-privacy": "github:ActivistChecklist/umami-extra-privacy#<commit-sha>"
  }
}
```

Pin to a commit SHA so a renamed branch can't silently change your dep.

## Configuration (env)

The package reads these by default. Cloud takes precedence over self-hosted
when both are set.

| Variable | Used for | Required |
|---|---|---|
| `UMAMI_WEBSITE_ID` | Website to send events to | yes (both modes) |
| `UMAMI_API_KEY` | Cloud auth | cloud only |
| `UMAMI_API_CLIENT_USER_ID` | Self-hosted auth | self-hosted only |
| `UMAMI_API_CLIENT_SECRET` | Self-hosted auth | self-hosted only |
| `UMAMI_API_CLIENT_ENDPOINT` | Umami host (e.g. `https://umami.example.com`) | self-hosted (cloud optional) |
| `UMAMI_HOST` | Fallback for `UMAMI_API_CLIENT_ENDPOINT` | no |
| `IP_HASH_SALT` | Salt for `hash` / `geo-hash` levels | hashing levels only |

You can also pass `config` and `salt` directly to the handler — config wins
over env.

## Anonymization levels

Pass via the `level` option. Default: `geo-hash`.

| Level | IPv4 behavior | IPv6 behavior | Geo info | Reversible? |
|---|---|---|---|---|
| `none` | unchanged | unchanged | full | yes (passes raw IP) |
| `mask24` | last octet zeroed (`/24`) | last 5 groups zeroed (`/48`) | very coarse | no |
| `mask16` | last two octets zeroed (`/16`) | last 4 groups zeroed (`/64`) | coarse | no |
| `geo-hash` | first 2 octets kept, top 3 bits of octet 3 kept, rest randomized via salted hash | first 3 groups kept, group 4 randomized via salted hash | coarse | no |
| `hash` | full 64-char SHA-256 hex (no IP shape) | full 64-char SHA-256 hex | none | no |
| `drop` | omitted from payload | omitted from payload | none | n/a |

Notes:

* For `hash` and `geo-hash`, you must provide a salt. Default `rotation` is
  `daily`, so the hash for a given IP changes once per UTC day. Options are
  `daily` / `hourly` / `none`.
* `geo-hash` deliberately preserves enough information for Umami's IP-to-geo
  lookup to land in the right country/region while making per-visitor tracking
  impractical. If you don't need geo, prefer `hash` or `drop`.
* Invalid IP strings (junk, IPv6 with embedded IPv4, malformed IPv6) pass
  through unchanged for `mask*` levels and are still hashed for `hash` /
  `geo-hash`.

## Adapters

### Fastify

```ts
import Fastify from 'fastify';
import { createFastifyPlugin } from '@activistchecklist/umami-extra-privacy/fastify';

const app = Fastify();

await app.register(createFastifyPlugin({
  route: '/counter',
  level: 'geo-hash',
  // salt: defaults to process.env.IP_HASH_SALT
  // config: defaults to process.env.UMAMI_*
}));

await app.listen({ port: 3000 });
```

Rate limiting is your responsibility. With `@fastify/rate-limit` registered:

```ts
await app.register(createFastifyPlugin({
  rateLimit: { max: 200, timeWindow: '1 minute' },
}));
```

### Next.js App Router

```ts
// app/api/counter/route.ts
import { createRouteHandler } from '@activistchecklist/umami-extra-privacy/next';

export const POST = createRouteHandler({ level: 'geo-hash' });
```

For rate limiting, wrap the handler or use middleware (e.g.
[@upstash/ratelimit](https://github.com/upstash/ratelimit-js)).

### Generic / any framework

```ts
import {
  createCounterHandler,
  extractClientIp,
} from '@activistchecklist/umami-extra-privacy';

const handle = createCounterHandler({ level: 'mask24' });

// Inside your framework's POST handler:
const result = await handle({
  ip: extractClientIp(req.headers, req.socket.remoteAddress),
  userAgent: req.headers['user-agent'],
  body: parsedJsonBody,
  host: req.headers.host,
  referer: req.headers.referer,
});
// result.status is 200 | 400 | 500 | 502
```

## Browser helper

```ts
// in a client component
import { sendAnalytics } from '@activistchecklist/umami-extra-privacy/client';

await sendAnalytics(); // auto page-view
await sendAnalytics({ name: 'signup_started', data: { plan: 'pro' } });

// Skip in dev:
await sendAnalytics(
  { name: 'click' },
  { skip: () => process.env.NODE_ENV !== 'production' }
);
```

The helper auto-fills `url`, `referrer`, `hostname`, `title`, `userAgent`,
`screen`, and `language` from the browser. Failures return `null` instead of
throwing.

## Low-level API

For advanced use, the package exports:

* `anonymizeIp(ip, options)` — pure anonymization, no I/O
* `sendUmamiEvent({ config, payload, userAgent })` — pure send, no IP handling
* `resolveConfigFromEnv(env?)` — env → `UmamiConfig | null`
* `extractClientIp(headers, fallback?)` — leftmost XFF / X-Real-IP / fallback

## Security notes

* Never log raw IPs anywhere upstream of this handler. Anonymization happens
  inside the handler — if you log the request body or raw socket address
  before calling the handler, you've leaked.
* The `IP_HASH_SALT` should be a cryptographically random server-only secret.
  If it leaks, the daily rotation is your only remaining protection against
  rainbow-table reversal of the hash.
* The package does not bundle CORS, helmet, or rate limiting. Configure those
  on your app — see your framework's docs.

## License

MIT

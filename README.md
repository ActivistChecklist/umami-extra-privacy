# @activistchecklist/umami-extra-privacy

This packages adds a thin layer of additional privacy features on top of Umami [Umami](https://umami.is/) analytics.

* Sends Umami requests to a server-side API before sending them to the actual Umami instance. (Can be self-hosted or use Umami Cloud). This gives us control over what we send, and ensures that our user is never connecting to a server other than ours, for maximum privacy.
* (Optional) Trims off some data from the IP address so you can still get the user's approximate location without ever sending it to the server. (This is the `geo-hash` option.)

**Why does this matter?** If your Umami database is turned over to law enforcement, you now no longer have the exact IP addresses of your visitors. There is plausible deniability that any given person actually viewed your site.

**Doesn't Umami already obfuscate the IP addresses?** Yes, Umami generates a hash of IP addresses rather than storing the original. But if someone knows your APP_SECRET, the user agent, and the IP address, they can reverse engineer the hash and determine if a particular user was on your site. With `hash` or `geo-hash`, the IP Umami receives comes from a random key that exists only in this process's memory and is thrown away every day. After that, nobody (including you) can work out which stand-in a real IP address was given, so a guessed IP can no longer be matched to a session.

## What this package includes

* **6 anonymization levels** from `none` to `drop`, including a geo-preserving
  stand-in address keyed by a random daily key that is never stored.
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

Pin to the full SHA of a commit on `main` (each release is also tagged
`vX.Y.Z`) so a renamed branch can't silently change your dep. Don't pin a
PR-branch commit: PRs are squash-merged, so it never lands on `main`.

The package builds itself with a `prepare` script when it installs. pnpm 10
and later skip dependency build scripts unless you allow them, and then
`dist/` is missing. pnpm 12 also wants the allowance to name the exact
tarball, so update it with every new SHA:

```yaml
# pnpm-workspace.yaml
allowBuilds:
  "@activistchecklist/umami-extra-privacy@https://codeload.github.com/ActivistChecklist/umami-extra-privacy/tar.gz/<commit-sha>": true
```

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

You can also pass `config` directly to the handler. It wins over env.

`IP_HASH_SALT` is no longer used. The hashing levels need no secret of your
own, so you can delete it.

## Anonymization levels

Pass via the `level` option. Default: `geo-hash`.

| Level | IPv4 behavior | IPv6 behavior | Geo info | Reversible? |
|---|---|---|---|---|
| `none` | unchanged | unchanged | full | yes (passes raw IP) |
| `mask24` | last octet zeroed (`/24`) | last 5 groups zeroed (`/48`) | very coarse | no |
| `mask16` | last two octets zeroed (`/16`) | last 4 groups zeroed (`/64`) | coarse | no |
| `geo-hash` | first 19 bits kept, last 13 shuffled with the daily key | first 28 bits kept, bits 28-63 shuffled with the daily key, last 64 zeroed | coarse | no, once the key is gone |
| `hash` | 64-char HMAC-SHA256 hex with the daily key (no IP shape) | same | none | no, once the key is gone |
| `drop` | omitted from payload | omitted from payload | none | n/a |

Notes:

* `hash` and `geo-hash` use a random 32-byte key made with
  `crypto.randomBytes`. It is never derived from a secret, written to disk or
  logged. Default `rotation` is `daily`: at each UTC midnight the key is wiped
  and a new one is made, even if no request comes in. Options are `daily` /
  `hourly` / `none` (`none` keeps one key until the process exits).
* Within a period the same IP always gets the same stand-in, so Umami's
  sessions still work. After the period, the stand-in can't be traced back to
  the real IP, even by someone who has your server, your env files and your
  Umami database.
* The key lives in one process. A restart starts a new key, so a visitor who
  is active across the restart shows up as two sessions that day. Running
  several instances (PM2 cluster mode, serverless) gives each its own key,
  which splits a visitor into one session per instance. Run a single
  long-running process if session counts matter to you.
* Someone who can read the running process's memory can get the current
  day's key. Past days stay safe.
* `geo-hash` shuffles with a keyed permutation, so two visitors in the same
  block never share a stand-in. It keeps enough of the address for Umami's
  IP-to-geo lookup to land in roughly the right region. If you don't need geo,
  prefer `hash` or `drop`.
* IPv4-mapped IPv6 (`::ffff:203.0.113.5`) is treated as the IPv4 address it
  wraps, and ports (`203.0.113.5:443`, `[2001:db8::1]:443`) are stripped.
  Anything that still isn't an IP address returns `null` for every level
  except `none`, so it is left out of the payload rather than sent as is.

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

* `anonymizeIp(ip, options)`: anonymization only, no I/O (the hashing levels keep their key in memory)
* `sendUmamiEvent({ config, payload, userAgent })` — pure send, no IP handling
* `resolveConfigFromEnv(env?)` — env → `UmamiConfig | null`
* `extractClientIp(headers, fallback?)` — leftmost XFF / X-Real-IP / fallback

## Security notes

* Never log raw IPs anywhere upstream of this handler. Anonymization happens
  inside the handler — if you log the request body or raw socket address
  before calling the handler, you've leaked.
* The hashing levels keep their key in memory only. Don't add code that
  persists or logs it, and don't swap it for a key derived from a stored
  secret: anyone with that secret could then reverse every past day.
* The package does not bundle CORS, helmet, or rate limiting. Configure those
  on your app — see your framework's docs.

## License

MIT

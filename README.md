# Captcha Protect

[![lint-test](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml/badge.svg)](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml)
[![codecov](https://codecov.io/gh/libops/captcha-protect/branch/main/graph/badge.svg)](https://codecov.io/gh/libops/captcha-protect)

Captcha Protect is a Traefik middleware that challenges client IPs on protected routes. It can use Turnstile, reCAPTCHA, hCaptcha, proof-of-javascript, or self-hosted Cap for the challenge.

It requires Traefik `v3.6` or above.

## Documentation

<https://captcha-protect.libops.io/>

## Self-hosted Cap

[Cap](https://trycap.dev) is an open-source proof-of-work CAPTCHA you can host yourself. With `captchaProvider: cap`, the challenge page loads the Cap widget and its WASM solver from your own Cap instance, solves automatically, and submits. No third-party service is contacted.

| Option | Description |
|---|---|
| `captchaProvider` | `cap` |
| `siteKey` / `secretKey` | A site key and its secret key, created in the Cap dashboard |
| `capURL` | Cap's base URL as the browser sees it, e.g. `/cap` (same host) or `https://example.com/cap`; must be on the same origin as the protected site unless you configure CORS origins on the Cap site key |
| `capVerifyURL` | Base URL the middleware uses to call Cap's siteverify from inside Traefik, e.g. `http://cap:3000/cap`. Required when `capURL` is a path; defaults to `capURL` otherwise |

Cap must run with `ENABLE_ASSETS_SERVER=true` so it serves `/assets/widget.js` and `/assets/cap_wasm_bg.wasm`. The widget is visible while it solves; a custom challenge template with `data-appearance="interaction-only"` keeps it hidden. The circuit breaker (`periodSeconds` / `failureThreshold`) probes `{capVerifyURL}/assets/widget.js` and falls back to proof-of-javascript while Cap is down.

### Example: Cap on `/cap` behind Traefik

Cap needs `BASE_PATH` support ([tracyhatemice/cap](https://github.com/tracyhatemice/cap)) to be served under a subpath without StripPrefix. Traefik and Cap must share a Docker network.

```yaml
services:
  cap:
    build:
      context: https://github.com/tracyhatemice/cap.git#main
      dockerfile: standalone/Dockerfile
    environment:
      ADMIN_KEY: change-me-to-a-long-random-secret
      REDIS_URL: redis://valkey:6379
      BASE_PATH: /cap
      ENABLE_ASSETS_SERVER: "true"
      WIDGET_VERSION: "0.1.57"
      WASM_VERSION: "0.0.7"
    labels:
      traefik.enable: "true"
      traefik.http.routers.cap.rule: Host(`example.com`) && (Path(`/cap`) || PathPrefix(`/cap/`))
      traefik.http.services.cap.loadbalancer.server.port: "3000"
  valkey:
    image: valkey/valkey:9-alpine
  site:
    labels:
      traefik.http.routers.site.rule: Host(`example.com`)
      traefik.http.routers.site.middlewares: captcha-protect@docker
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.captchaProvider: cap
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.siteKey: ${CAP_SITE_KEY}
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.secretKey: ${CAP_SECRET_KEY}
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.capURL: /cap
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.capVerifyURL: http://cap:3000/cap
      traefik.http.middlewares.captcha-protect.plugin.captcha-protect.protectRoutes: /
```

1. Start Cap, open `https://example.com/cap/`, log in with `ADMIN_KEY`, and create a site key.
2. Put the site key and secret key into the middleware config.

The `cap` router's rule is longer than the site's, so Traefik matches it first and Cap's own requests are never challenged. If the middleware is attached to a parent router (multi-layer routing), add `/cap/` to `excludeRoutes` (`^/cap(/|$)` in regex mode). In prefix mode, `/cap/` alone is enough because the bare `/cap` URL only 301-redirects to it; don't exclude the prefix `/cap` itself, since that would also exclude unrelated site pages like `/capabilities`.

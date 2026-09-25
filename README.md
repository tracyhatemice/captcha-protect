# Captcha Protect

[![lint-test](https://github.com/tracyhatemice/captcha-protect/actions/workflows/lint-test.yml/badge.svg)](https://github.com/tracyhatemice/captcha-protect/actions/workflows/lint-test.yml)

Captcha Protect is a Traefik middleware that challenges client IPs on protected routes. It can use Turnstile, reCAPTCHA, hCaptcha, proof-of-javascript, or self-hosted Cap for the challenge.

## Verification by browser session

Set `verificationMode: session` to require each browser session to solve its own challenge, even when several visitors share an IP address. The default is `ip` for compatibility with existing configurations. For Docker labels:

```yaml
traefik.http.middlewares.captcha-protect.plugin.captcha-protect.verificationMode: session
```

After a successful challenge, the middleware sets a host-only, HTTP-only cookie scoped to `/`. The cookie lasts for `window` seconds (one hour when the circuit breaker fallback is active). Browsers that block or clear cookies will need to solve the challenge again. A copied cookie grants the same access until it expires, so use HTTPS for protected sites. IP exemptions and bot exemptions still apply in either mode.

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

Cap must run with `ENABLE_ASSETS_SERVER=true` so it serves `/assets/widget.js` and `/assets/cap_wasm_bg.wasm`. The circuit breaker (`periodSeconds` / `failureThreshold`) probes `{capVerifyURL}/assets/widget.js` and falls back to proof-of-javascript while Cap is down.

Two attributes on the challenge template's captcha element control the widget, following Turnstile's naming:

| Attribute | Value | Behaviour |
|---|---|---|
| `data-appearance` | `always` (default), `execute` | Widget is visible |
| `data-appearance` | `interaction-only` | Widget is hidden |
| `data-execution` | `render` (default), missing | Solves as soon as the widget loads |
| `data-execution` | `execute` | Waits for the visitor to click the widget |

`data-execution="execute"` needs a widget the visitor can click, so it overrides `data-appearance="interaction-only"` and logs a warning.

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

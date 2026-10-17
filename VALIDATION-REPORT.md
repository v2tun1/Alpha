# Alpha Stage 6 — Deployment Readiness Validation

## Passed locally

- [PASS] `node --check alpha-core.js`
- [PASS] `node --check alpha-mask.js`
- [PASS] `bash -n alpha-relay.sh`
- [PASS] `premium-index.json` parses as JSON
- [PASS] `wrangler.jsonc` parses as JSON
- [PASS] Local asset directory contains `alpha-mask.js`, `network-index.dat`, `premium-index.json`, `bulletin.dat`, `data/regions/`, and `data/premium/`
- [PASS] Main UI asset fallback no longer points at the previously hard-coded third-party Worker/GitHub placeholder; it requests same-origin assets
- [PASS] ZIP archive integrity checked after packaging

## Not yet verified

- [NOT RUN] `npm install` / Wrangler CLI validation in this environment
- [NOT RUN] `wrangler deploy --dry-run`
- [NOT RUN] Actual Cloudflare Workers deployment
- [NOT RUN] Remote D1 binding/schema behavior on a Cloudflare account
- [NOT RUN] Browser end-to-end tests for login, session expiry, user CRUD, subscriptions, and WebSocket flows
- [NOT RUN] Full security review or penetration test

This package is suitable for a controlled staging test after installing Wrangler and configuring the required secret. It must not yet be treated as production-approved.

# Alpha Network Toolkit

Alpha is a Cloudflare Workers-based proxy management and network utility project.

## Project layout

- `alpha-core.js` — Worker entry point and application logic.
- `alpha-mask.js` — bundled auxiliary JavaScript asset.
- `alpha-relay.sh` — optional SOCKS5 relay administration script.
- `alpha-scan.dat` — scanner utility payload.
- `network-index.dat` — network address source list.
- `premium-index.json` — index of premium region datasets.
- `bulletin.dat` — optional announcement content.
- `release.dat` — release metadata.
- `data/regions/` — standard region datasets (`region-XX.dat`).
- `data/premium/` — premium region datasets (`premium-XX.dat`).
- `media/` — project screenshots and visual assets.

## Deployment notes

1. Remote self-update is disabled by default. Only set `ALLOW_REMOTE_UPDATES=1` after reviewing the update source and accepting that it can replace the running Worker.
2. Set a random `ADMIN_SETUP_KEY` secret (at least 24 characters) in Worker settings before first setup. Keep it private.
3. Deploy `alpha-core.js` as the Cloudflare Worker entry point.
4. Publish the data and supporting assets at the repository paths referenced by the Worker.
5. In `alpha-core.js`, replace the `OWNER/Alpha` placeholder in the raw GitHub URL with the actual repository owner and repository name.
6. Verify Worker routes, environment bindings, database schema, and external service URLs in your own environment before production use.
7. Do not expose credentials, tokens, or private infrastructure values in a public repository.

The original repository's third-party service URLs and deployment assumptions may not apply to a new Alpha deployment.

## Security changes in this build

- First-time password setup requires the `ADMIN_SETUP_KEY` Worker secret.
- Privileged API access fails closed until an administrator password exists.
- Proxy testing now requires an authenticated panel session.
- New and changed panel passwords must be at least 12 characters.
- IP geolocation requests use HTTPS.

This is a static hardening pass, not a substitute for a deployed penetration test.

## Code review note

This build separates the session bearer token from the password digest and limits the session cookie to 12 hours. Sign in again once after upgrading. See `STAGE4-CODE-REVIEW-fa.md` for details.

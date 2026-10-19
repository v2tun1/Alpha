# Alpha

Restructured Cloudflare Workers project.

- `src/worker.js`: Worker entry point
- `public/data/`: local IP, message, version, and proxy data
- `public/assets/images/`: project images
- `public/tools/`: relay manager and scanner bundle
- `public/vendor/`: preserved obfuscated JavaScript artifact
- `public/downloads/worker-source.js`: downloadable source mirror, synchronized before deploy
- `wrangler.jsonc`: Worker, static assets, and D1 configuration

Run `npm install`, `npm run check`, `npm run deploy:dry`, then `npm run deploy` after verifying the D1 database ID belongs to your Cloudflare account. Project data files are served locally from `public/`; Cloudflare APIs and some third-party services remain external integrations.

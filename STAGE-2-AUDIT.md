# Alpha — Stage 2 audit

## Completed

- Replaced remaining visible legacy project branding in the Worker UI and scanner title with `Alpha`.
- Updated the WebSocket integrity guard to check the new `Alpha` brand so the rename does not intentionally disable that path.
- Replaced embedded instruction-like strings with neutral runtime marker text; these strings were not application functionality.
- Fixed the update-panel asset name to `alpha-mask.js`, matching the renamed file.
- Pointed relay/scanner download examples at the renamed files in the Alpha repository.
- Removed the hard-coded third-party `workers.dev` asset/update fallback. Asset retrieval now uses the Alpha GitHub repository path only.
- Kept data filenames and runtime references aligned with `data/regions/`, `data/premium/`, `network-index.dat`, and `premium-index.json`.

## Required before deployment

1. Replace `OWNER` in the raw GitHub URLs with the real GitHub owner/org that will host Alpha.
2. Verify that the repository branch is `main`, or update the branch segment in the URLs.
3. Test Cloudflare Worker bindings and all update/deployment routes in a staging environment before production.

## Validation performed

- JavaScript syntax check: `alpha-core.js` — passed.
- JavaScript syntax check: `alpha-mask.js` — passed.
- Shell syntax check: `alpha-relay.sh` — passed.
- JSON parse check: `premium-index.json` — passed.
- Archive integrity and internal file-path checks — see release notes.

## Known follow-up

The `data/premium/` datasets contain proxy endpoint records whose usernames include the legacy word `zeus`. These are data credentials/endpoint identifiers, not project labels; they were not rewritten because altering them could invalidate those endpoints. Review whether these endpoints are still authorized and current before production use.

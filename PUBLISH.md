# Publishing this pack

Everything here is staged and validated. Two steps remain, and **both push to a remote**, so they
are left for you to run.

## 1. Publish the content repo

```bash
cd /Users/frost/Desktop/projects/vineyard
./publish-packs.sh pluginpack-whatsmyname
```

This does three things with remote effect — `git init` + commit (local), **`gh repo create
Vineyard-Intelligence/pluginpack-whatsmyname --public`**, and **`git push -u origin main`**. It then
prints the commit SHA under "Published packs (pin these commit SHAs in the registry)". Copy it.

Dry-run first if you want to see it without changing anything:
`./publish-packs.sh --dry-run pluginpack-whatsmyname` (already run; output was as expected).

## 2. List it in the registry catalog

Append this entry to `registry/registry/community-pluginpacks.json` (a top-level JSON array, 7
entries today), replacing `REPLACE_WITH_COMMIT_SHA` with the SHA from step 1 — the catalog rejects
tags and branches, only a 40-hex commit:

```json
{
  "identifier": "run.vineyard.pluginpacks.whatsmyname",
  "content_type": "vineyard:pluginpack",
  "name": "WhatsMyName",
  "author": "vineyard-run",
  "description": "Checks whether a username exists across roughly 700 sites using the WhatsMyName dataset and adds the discovered accounts to the graph. Desktop only: a browser cannot read the cross-origin responses these checks depend on.",
  "repo": "Vineyard-Intelligence/pluginpack-whatsmyname",
  "ref": "REPLACE_WITH_COMMIT_SHA",
  "path": "plugins/whatsmyname.manifest.json",
  "version": "1.0.0",
  "platforms": ["desktop"],
  "scopes_summary": {
    "network": true,
    "graph_write": true,
    "publish": false,
    "secret_config": false
  },
  "plugin_count": 1,
  "compat": { "min_app_version": "0.1.0" },
  "verified": true
}
```

Then commit and **push the `registry` repo**. CI (`validate.py` + `verify_pinned.py`) will re-fetch
the pinned commit through jsDelivr and assert the manifest's `identifier` / `content_type` match.

## Notes on two fields

- **`platforms: ["desktop"]`** — deliberately not `["web","desktop"]`, even though the manifest
  carries a `platforms.web` block. That block exists because the runner only ever executes the
  `platforms.web` sandbox-js entry; it is *how* the plugin runs, not *where it works*. The pack is
  useless in a browser, so the catalog badge says desktop.
- **`compat.min_app_version: "0.1.0"`** — the desktop shell version that introduced the `web_probe`
  capability this pack depends on. Sibling packs say `1.0.0` because they have no such dependency.

## What is NOT required

No bundle build. Like all seven currently-published packs, the code ships as a built-in reference
plugin inside the app (`frontend/…/plugins/reference/whatsmyname-pack.ts`, manifest `entry:
"inline"`); this repo is the catalog stub. `dist/` stays a placeholder until remote bundles are a
real path.

# WhatsMyName

A Vineyard **plugin pack** for OSINT username enumeration. Given a **User Account** (or **Person**)
node, it checks whether that handle is registered across ~700 sites using the
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset (CC-BY-SA-4.0), and adds each
discovered account to the graph.

## Desktop only

This pack runs **only in the Vineyard desktop app**, and that is a property of the problem, not a
choice. WhatsMyName decides "this account exists" from a site's HTTP **status code** (and sometimes a
substring of the body). Reading that requires reading a **cross-origin** response from a site that
sends no CORS headers — which a browser will not do; the response is opaque. The desktop app's
Electron main process has no same-origin policy, so it can make the request and read the result.

In a browser the plugin is present but inert: it detects that the capability is missing and tells you
to open the project in the desktop app rather than returning a misleading empty result.

## How it works

- The **site list** is fetched live from jsDelivr
  (`cdn.jsdelivr.net/gh/WebBreacher/WhatsMyName@main/wmn-data.json`), which serves it with
  `access-control-allow-origin: *`, so the plugin always has the latest dataset.
- Each site is then checked with **one direct request** through the desktop shell's `web_probe`
  capability. That request is:
  - **anonymous** — no cookies and no credentials are attached, so it sees only what a logged-out
    visitor sees;
  - **redirect-free** — a 302-to-login reads as "no account", not a masked success;
  - **SSRF-guarded** — http(s) only, standard ports only, and loopback / private / link-local /
    reserved addresses (and public names that resolve to them) are refused.
- A site counts as a hit when the response **status matches** the dataset's `e_code` **and** (if the
  entry specifies one) the `e_string` appears in the body — the same rule as upstream WhatsMyName.

Each hit becomes one **User Account** node (`username` carries `handle · Site` so platforms stay
distinct, the bare handle is kept in `display_name`), linked to the seed with a `same handle` edge.

## Layout

- `plugins/whatsmyname.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle (see note; not built yet — the plugin runs as a built-in in-app today).

Data source: the WhatsMyName dataset (`github.com/WebBreacher/WhatsMyName`, via jsDelivr). No
credentials, no server, no cost.

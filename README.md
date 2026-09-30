# WhatsMyName

A Vineyard **plugin pack** for OSINT username enumeration. Given a **Handle**, **Account**,
**Social Account**, **Person**, or **Email Address** node, it checks whether that handle is
registered across ~700 sites using the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
dataset (CC-BY-SA-4.0), and adds each discovered account to the graph.

## Desktop only

This pack runs **only in the Vineyard desktop app**. WhatsMyName decides "this account exists" from a
site's HTTP **status code** (and sometimes a substring of the body), and sites that send no CORS
headers do not let a browser read either.

In a browser the plugin is present but inert: it detects that the capability is missing and tells you
to open the project in the desktop app rather than returning a misleading empty result.

## How it works

- The **site list** is fetched live from jsDelivr
  (`cdn.jsdelivr.net/gh/WebBreacher/WhatsMyName@main/wmn-data.json`), so the plugin always has the
  latest dataset.
- Each site is then checked with **one direct request**. That request is:
  - **anonymous** — no cookies and no credentials are attached, so it sees only what a logged-out
    visitor sees;
  - **redirect-free** — a 302-to-login reads as "no account", not a masked success.
- A site counts as a hit when the response **status matches** the dataset's `e_code` **and** (if the
  entry specifies one) the `e_string` appears in the body — the same rule as upstream WhatsMyName.

Each hit becomes one **Account** node — `username` is the bare handle and `platform` names the
website, which together are the node's identity — linked to the seed with a `same handle` edge.

## Layout

- `plugins/whatsmyname.manifest.json` — the pack manifest (catalog entry source).
- `dist/pack.mjs` — the runnable bundle.

Data source: the WhatsMyName dataset (`github.com/WebBreacher/WhatsMyName`, via jsDelivr). No
credentials, no server, no cost.

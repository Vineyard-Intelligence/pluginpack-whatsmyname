// WhatsMyName — OSINT username enumeration (desktop-native).
//
// Checks whether a username/handle is registered across ~700 sites using the WhatsMyName dataset
// (https://github.com/WebBreacher/WhatsMyName, CC-BY-SA-4.0).
//
// WHY THIS IS A DESKTOP PLUGIN. WhatsMyName decides "account exists" from a site's HTTP status
// code (and sometimes a body substring), which means the check must READ a cross-origin response
// from a site that sends no CORS headers. A browser cannot: the response is opaque. The earlier
// version of this plugin worked around that by POSTing site batches to a stateless Cloudflare
// Worker that ran the checks server-side. The Electron shell removes the need for that hop — its
// main process has no same-origin policy — so this version calls each site DIRECTLY through
// `ctx.net.probe`, an anonymous, SSRF-guarded, redirect-free request performed by the main
// process. No Worker, no shared endpoint to protect, no rate-limit tokens.
//
// The two network surfaces:
//   1. The DATASET — fetched from jsDelivr (which serves it `access-control-allow-origin: *`), so
//      the plugin always has the latest site list. This still uses ordinary `ctx.net.fetch`.
//   2. The CHECKS — one `ctx.net.probe` per site. Present only in the desktop shell; in a browser
//      the capability is absent and the plugin says so rather than half-working.
import { definePlugin, definePluginPack } from './sdk';
import type { HostContext, RunResult } from './sdk';

// Latest WhatsMyName dataset via jsDelivr (CDN + CORS). `@main` tracks the live DB (≈12 h edge
// cache); pin to a commit SHA instead for a reproducible snapshot.
const WMN_DATA_URL = 'https://cdn.jsdelivr.net/gh/WebBreacher/WhatsMyName@main/wmn-data.json';

// One probe per site, run with this many in flight. Matched to the main process's own probe
// ceiling (probe.ts MAX_CONCURRENT) so the pipeline stays full without queuing behind it.
const CONCURRENCY = 48;

// Cap on a probed body when a site's detection needs a body substring — the whole point is giving
// `e_string` somewhere to be found.
const BODY_CAP_BYTES = 256 * 1024;

// Cap on a probed body when a site's detection is status-code-only. Small, and NOT zero: a 0-byte
// cap (this file's old default here) still drains and discards the WHOLE response before resolving
// — see desktop's probe.ts, which only finishes early on a POSITIVE maxBytes that gets hit before
// the stream ends. So reading a small slice instead of none is not a new cost, it can only resolve
// SOONER, and it is what makes the antibot signature scan below possible on sites that never
// declared an `e_string` to read a body for in the first place. 8 KB is comfortably past where a
// WAF/challenge interstitial announces itself (title, meta tags, the first script block).
const ANTIBOT_SCAN_BYTES = 8 * 1024;

// Known WAF / anti-bot interstitial fingerprints, scanned case-insensitively against a response
// that already looks like a hit. Sourced from sherlock's WAFHitMsgs and the official WhatsMyName
// checker's BLOCKING_SIGNALS. Deliberately generic rather than an exhaustive per-vendor list —
// missing one here still falls through to the differential check below, which does not need to
// recognise WHAT blocked the request, only THAT something did.
const ANTIBOT_SIGNATURES = [
    'cloudflare',
    'cf-ray',
    'cf-chl',
    '__cf_chl',
    'just a moment',
    'checking your browser',
    'attention required',
    'enable javascript and cookies',
    'ddos-guard',
    'ddos protection by',
    'perimeterx',
    'captcha',
    'are you a robot',
    'access denied',
    'making sure you',
    "you're not a bot",
    'checking you are not a bot',
    'anubis',
] as const;

function looksLikeAntibot(body: string): boolean {
    const lower = body.toLowerCase();
    return ANTIBOT_SIGNATURES.some((sig) => lower.includes(sig));
}

/**
 * A control account for the differential check: same LENGTH and per-character CLASS as the real
 * handle (lowercase -> lowercase, uppercase -> uppercase, digit -> digit; anything else — dots,
 * underscores, hyphens, usually structural rather than the site's differentiator — left as-is).
 * `"hello1989"` -> something like `"xlyrt3458"`, not `"hello1989xk3"`: a suffix leaves the real
 * handle sitting inside the control as a substring, which a substring-based `e_string` check could
 * still match on its own, defeating the point of asking a DIFFERENT question. Preserving shape
 * rather than substituting a fixed or generic string also means the control still satisfies
 * whatever length/charset validation the real handle already passed, so a mismatch reflects the
 * site's own detection logic rather than the control getting rejected for looking wrong.
 *
 * `crypto.getRandomValues`, not `Math.random()` — no reason to reach for a weaker source of
 * per-character randomness when a stronger one is one call away.
 *
 * Returns null when the handle has no letter or digit to randomise at all (a handle made entirely
 * of separators) rather than silently returning it unchanged, which would make the "control"
 * identical to the real request and defeat the check outright.
 */
function randomAccount(handle: string): string | null {
    const bytes = new Uint8Array(handle.length);
    crypto.getRandomValues(bytes);
    let changed = false;
    const out = [...handle].map((ch, i) => {
        if (ch >= 'a' && ch <= 'z') {
            changed = true;
            return String.fromCharCode(97 + (bytes[i] % 26));
        }
        if (ch >= 'A' && ch <= 'Z') {
            changed = true;
            return String.fromCharCode(65 + (bytes[i] % 26));
        }
        if (ch >= '0' && ch <= '9') {
            changed = true;
            return String.fromCharCode(48 + (bytes[i] % 10));
        }
        return ch;
    });
    return changed ? out.join('') : null;
}

interface WmnSite {
    name?: string;
    cat?: string;
    uri_check?: string;
    uri_pretty?: string;
    e_code?: number;
    e_string?: string;
    m_code?: number;
    m_string?: string;
    valid?: boolean;
    strip_bad_char?: string;
    headers?: Record<string, string>;
    post_body?: string;
}

interface Hit {
    name: string;
    category?: string;
    profile_url: string;
    http_status: number;
}

/**
 * Pull a handle from the seed node: `handle`, `username`, `value`, a person's first alias, or —
 * for an email address — the local part before `@`. The local part is a common real username
 * (mail providers routinely allocate one 1:1 with the mailbox), so it's a reasonable username
 * guess even though it is not guaranteed to be the same handle the owner uses elsewhere.
 */
function handleFrom(node: { type: string; data: Record<string, unknown> }): string {
    const d = node.data || {};
    if (node.type === 'identity.person') {
        const aliases = String((d as any).aliases ?? '').trim();
        return aliases
            ? aliases
                  .split(/[,;\n]/)[0]
                  .trim()
                  .replace(/^@/, '')
            : '';
    }
    if (node.type === 'identity.email_address') {
        const email = String((d as any).email ?? '').trim();
        const at = email.indexOf('@');
        return at > 0 ? email.slice(0, at) : '';
    }
    // `handle` first: identity.handle is the type for a bare alias whose owner is not yet known,
    // which is the most common way an enumeration sweep actually starts.
    return String((d as any).handle ?? (d as any).username ?? '')
        .trim()
        .replace(/^@/, '');
}

/** Raw `{account}` substitution — exactly what the WhatsMyName dataset templates expect. */
function applyAccount(template: string, account: string): string {
    return template.split('{account}').join(account);
}

/**
 * Reject a handle that can't be checked safely.
 *
 * The dataset builds URLs by substituting the handle into templates, some of which put it in the
 * HOST position (`https://{account}.example.com`). A handle containing URL-structural characters
 * could therefore redirect the request onto a different host. The main-process probe guards the
 * final URL regardless, but refusing these up front is a cheaper, clearer failure — and matches
 * the reference Worker's own username guard.
 */
function badUsername(handle: string): boolean {
    if (!handle || handle.length < 1 || handle.length > 100) return true;
    if (/[/\\?#@:%]/.test(handle)) return true;
    if (/[\x00-\x1f\x7f]/.test(handle)) return true;
    return false;
}

/** A site is checkable only if it has the fields the detection rule needs and isn't flagged bad. */
function validForCheck(site: WmnSite): boolean {
    return (
        !!site &&
        site.valid !== false &&
        typeof site.name === 'string' &&
        typeof site.uri_check === 'string' &&
        Number.isFinite(site.e_code)
    );
}

/** WhatsMyName's "found" rule: the exact status AND (no e_string, or e_string present in body). */
function isFound(site: WmnSite, status: number, body: string): boolean {
    const eString = site.e_string == null ? '' : String(site.e_string);
    return status === site.e_code && (eString === '' || body.includes(eString));
}

/** One request for a given account string against a site. Shared by the real check and the
 *  differential control check below — they must go through the identical request shape or a
 *  mismatch would reflect the two requests, not the site's own detection logic. */
async function probeAccount(
    ctx: HostContext,
    site: WmnSite,
    acct: string,
    maxBytes: number,
): Promise<{ status: number; body: string } | null> {
    const url = applyAccount(site.uri_check as string, acct);
    const isPost = typeof site.post_body === 'string' && site.post_body.length > 0;
    const res = await ctx.net!.probe!(url, {
        method: isPost ? 'POST' : 'GET',
        headers: site.headers,
        body: isPost ? applyAccount(site.post_body as string, acct) : undefined,
        maxBytes,
    });
    // A guard rejection or transport error comes back as status 0 with `error` set — treat it as
    // "not found here" rather than aborting the whole sweep.
    if (res.error || res.status === 0) return null;
    return { status: res.status, body: res.body };
}

/**
 * Probe one site and decide whether the handle exists there.
 *
 * Everything past the first request only runs for a site that ALREADY looks like a hit — most of a
 * ~700-site sweep is a plain miss, decided on status code alone, and pays none of what follows.
 * That is what makes the extra requests below affordable: they land on the handful of sites per
 * sweep that actually claim a match, not on all of them.
 *
 * `e_code`/`e_string` alone (this file's check before this change) is the dataset's POSITIVE rule
 * only. The dataset also carries `m_code`/`m_string` for the "definitely absent" case, but nothing
 * here — or in Vineyard before this — ever compared a response against them; a generic error page,
 * a search-results fallback, or an antibot interstitial that happens to answer with the same status
 * (and no `e_string` to fail on) was indistinguishable from a real hit. Rather than start comparing
 * against `m_code`/`m_string` — which only tells you what the SITE AUTHOR expected a miss to look
 * like, not what THIS response actually is — the checks below ask the site directly: does a
 * DEFINITELY-nonexistent account get the same verdict as the real one? If it does, the site's
 * detection cannot currently tell real from fake, for whatever reason, and no per-site config value
 * fixes that.
 */
async function checkSite(
    ctx: HostContext,
    site: WmnSite,
    handle: string,
): Promise<{ found: boolean; status: number; profileUrl: string; blocked?: boolean } | null> {
    const acct = site.strip_bad_char
        ? [...handle].filter((c) => !String(site.strip_bad_char).includes(c)).join('')
        : handle;
    const profileUrl = applyAccount(site.uri_pretty || (site.uri_check as string), acct);

    const needBody = site.e_string != null && String(site.e_string) !== '';
    const readCap = needBody ? BODY_CAP_BYTES : ANTIBOT_SCAN_BYTES;

    const primary = await probeAccount(ctx, site, acct, readCap);
    if (!primary) return null;

    if (!isFound(site, primary.status, primary.body)) {
        return { found: false, status: primary.status, profileUrl };
    }

    // Looks like a hit. First: does the body announce a WAF/challenge page outright? Free — this
    // reuses the response already in hand, no extra request.
    if (looksLikeAntibot(primary.body)) {
        return { found: false, status: primary.status, profileUrl, blocked: true };
    }

    // No recognised antibot signature. Ask the site the same question about an account that
    // definitely does not exist. `null` means the handle had nothing to randomise (rare — all
    // separators) and can't be differential-tested; take the primary result as-is rather than
    // block on a check that cannot run.
    const control = randomAccount(acct);
    if (control === null) return { found: true, status: primary.status, profileUrl };

    const verify = async (ctrl: string): Promise<boolean> => {
        const res = await probeAccount(ctx, site, ctrl, readCap);
        // A failed control REQUEST proves nothing either way, and must never be allowed to suppress
        // a real finding — treat "could not check" the same as "did not match".
        return res ? isFound(site, res.status, res.body) : false;
    };

    if (!(await verify(control))) return { found: true, status: primary.status, profileUrl };

    // The control matched too — before concluding the SITE is unreliable, rule out the rarer but
    // real possibility that this one random string happens to be an actual account on this
    // particular site. A second, independently generated control squares that coincidence rather
    // than trusting a single draw. (`acct` is randomisable — the first call above already proved
    // that — so this one cannot return null.)
    const secondMatched = await verify(randomAccount(acct) as string);
    if (!secondMatched) return { found: true, status: primary.status, profileUrl };

    return { found: false, status: primary.status, profileUrl, blocked: true };
}

const whatsmyname = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.whatsmyname',
        content_type: 'vineyard:plugin',
        name: 'WhatsMyName Account Search',
        version: '2.2.2',
        description:
            'Checks whether each selected handle is registered on ~700 sites from the WhatsMyName dataset. Takes Handle, Account, Social Account or Email Address nodes (an email address uses its local part). Creates a Handle node (unless the seed is one), linked "uses handle" from the seed, and one Account per site where the handle was found (username, platform, profile_url), linked "same handle" from the Handle; likely false positives are counted as blocked and not added. Desktop only.',
        icon: 'at-sign',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'desktop',
            // The runner executes the sandbox-js entry the same way in both environments; the
            // desktop-only part is `ctx.net.probe`, which the shell provides and the browser does
            // not.
            //
            // This `entry` is inert. Nothing here is bundled — registry.ts's BUILTIN_ENTRIES is
            // empty on purpose — so the manifest the app actually reads is the JSON in
            // pluginpack-whatsmyname, whose entry points at the `dist/pack.mjs` that
            // build.mjs compiles from THIS file. Availability, io.consumes and the
            // runnable entry are all decided from that pinned catalog document; the object below
            // only travels inside the compiled module. Keep the two in step anyway: a reader who
            // trusts this block should not be misled about what ships.
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [
                // `handle` is the natural seed: a bare alias with no owner established yet, which
                // is exactly what a username sweep starts from. `account` still works for
                // pivoting off an account already attributed to a platform. `email_address` seeds
                // from the local part before `@` — a common real username, not a guaranteed one.
                // `social.account` (a platform profile a collector pack already staged — X, a
                // Telegram user, …) seeds the same way: handleFrom()'s generic fallback already
                // reads `username`, which is social.account's non-optional identity field, so no
                // parsing change was needed — only declaring the type here.
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'handle' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'account' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
                { typepack: 'run.vineyard.typepacks.social', category: 'social', name: 'account' },
            ],
            produces: [
                // The accounts, plus the bare handle they share. `handle` is one level of
                // abstraction above `account`: it names the actor without claiming which
                // person or organization it is, which is exactly what a name-based sweep
                // establishes. See the anchor block in run().
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'handle' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'account' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            network: [
                {
                    endpoint: WMN_DATA_URL,
                    methods: ['GET'],
                    purpose: 'Download the WhatsMyName site list.',
                },
            ],
            web_probe: {
                purpose: 'Check each WhatsMyName site for a profile under the handle.',
            },
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        const ids = ctx.input.selection;
        if (!ids.length)
            return {
                summary: 'Select an Account, Social Account, Handle, Person, or Email Address node first',
                counts: { found: 0 },
            };

        // Desktop-only: the per-site checks need `ctx.net.probe`, which exists only in the shell.
        // Fail loudly and usefully rather than returning zero hits that look like a clean miss.
        if (!ctx.net?.probe) {
            return {
                summary:
                    'WhatsMyName checks sites directly and needs the Vineyard desktop app — a browser cannot read these cross-origin responses. Open this project in the desktop app and run it again.',
                counts: { found: 0 },
            };
        }
        if (!ctx.net?.fetch) return { summary: 'Network capability not granted to this plugin', counts: { found: 0 } };

        // Pull the LATEST dataset from the CDN once for the whole selection (jsDelivr serves it
        // with CORS) — it does not depend on which node is being checked.
        const dataRes = await ctx.net.fetch(WMN_DATA_URL, { method: 'GET' });
        if (!dataRes.ok) throw new Error(`dataset fetch returned HTTP ${dataRes.status}`);
        const data = (await dataRes.json()) as { sites?: WmnSite[] };
        const sites = (Array.isArray(data.sites) ? data.sites : []).filter(validForCheck);
        const total = sites.length;
        if (!total) return { summary: 'WhatsMyName dataset was empty', counts: { found: 0 } };

        let found = 0;
        let handles = 0;
        let accounts = 0;
        let checked = 0;
        let noHandle = 0;
        let badHandle = 0;
        let notFound = 0;
        let blocked = 0;
        let processed = 0;
        let lastHandle = '';
        let lastHits = 0;
        let lastChecked = 0;

        // ONE node's handle at a time, not `Promise.all` across the selection: the concurrency
        // budget (CONCURRENCY, matched to the desktop probe's own ceiling) is already spent
        // sweeping ~700 sites for a SINGLE handle. Running several handles at once would not sweep
        // faster — it would divide that same ceiling across them and queue underneath it either
        // way, just with worse progress reporting and a harder-to-read failure if one handle's
        // sweep throws.
        for (let n = 0; n < ids.length; n++) {
            if (ctx.signal?.aborted) {
                return {
                    summary: `Cancelled after ${n}/${ids.length} node(s) (${found} found)`,
                    counts: {
                        found,
                        handles,
                        accounts,
                        checked,
                        no_handle: noHandle,
                        bad_handle: badHandle,
                        not_found: notFound,
                        blocked,
                    },
                };
            }
            const seed = await ctx.graph!.get!(ids[n]);
            if (!seed) {
                notFound++;
                continue;
            }
            const handle = handleFrom(seed);
            if (!handle) {
                noHandle++;
                continue;
            }
            if (badUsername(handle)) {
                badHandle++;
                continue;
            }
            lastHandle = handle;

            // Check every site directly, with bounded concurrency. A failed site never aborts the
            // sweep, and a failed node never aborts the run — see the loop's own catch below.
            const hits: Hit[] = [];
            let nodeChecked = 0;
            let nodeBlocked = 0;
            let done = 0;
            const base = Math.round((100 * n) / ids.length);
            const span = 100 / ids.length;
            const report = () =>
                ctx.progress?.set?.({
                    percent: Math.min(100, Math.round(base + (span * done) / total)),
                    message:
                        ids.length > 1
                            ? `"${handle}" (${n + 1}/${ids.length}) — ${hits.length} found · ${done}/${total} sites`
                            : `${hits.length} found · ${done}/${total} sites`,
                });

            let cursor = 0;
            const sweep = async () => {
                while (cursor < total) {
                    if (ctx.signal?.aborted) return;
                    const site = sites[cursor++];
                    try {
                        const r = await checkSite(ctx, site, handle);
                        if (r) {
                            nodeChecked++;
                            if (r.found) {
                                hits.push({
                                    name: site.name as string,
                                    category: site.cat,
                                    profile_url: r.profileUrl,
                                    http_status: r.status,
                                });
                            } else if (r.blocked) {
                                // Looked like a hit, failed the antibot signature check or the
                                // differential control check — no node, no edge, counted separately
                                // so the analyst can tell "checked and clean" from "checked and
                                // could not be trusted" instead of both collapsing into a silent miss.
                                nodeBlocked++;
                            }
                        }
                    } catch {
                        /* a failed site must not abort the whole sweep */
                    }
                    done++;
                    if (done % 10 === 0 || done === total) report();
                }
            };
            await Promise.all(Array.from({ length: Math.min(CONCURRENCY, total) }, sweep));
            report();

            // One account per discovered website, linked to the seed with an honest
            // "same handle" edge.
            //
            // `username` is the bare handle. It used to carry the label `"handle · Site"` because
            // host-bridge de-duped the account on `username` alone, so every platform collapsed
            // into one node otherwise. That put presentation into a data field: anything reading
            // `username` — a later plugin, an export, the agent — got a string that is not the
            // username. The typepack now declares `identity_properties: ["username", "platform"]`,
            // so (handle, site) is the identity and `username` can be the username again.
            // The bare handle becomes a node of its own, and the accounts hang off IT rather than
            // off whatever was selected.
            //
            // `identity.handle` is the abstraction a name sweep actually establishes: a name used
            // by someone whose identity is not settled yet. Seeded from a Person (via an alias) or
            // from one platform's account, the handle itself previously existed only as a string
            // inside another node, so the one fact the sweep proved — these accounts share a
            // NAME — had nothing to attach to. Rooting them on the handle states exactly that, and
            // no more: it is the anchor the account-pivot playbook tells the analyst to corroborate
            // FROM before drawing any "same person" conclusion.
            //
            // A sweep already seeded from a handle node reuses the seed. Re-running never adds a
            // second handle either — createNode de-dups on the type's identity (`handle`).
            let anchorId = String(seed.id);
            if (seed.type !== 'identity.handle') {
                const hNode = await ctx.graph!.createNode!({
                    type: 'identity.handle',
                    data: { handle, first_seen_context: 'Enumerated across sites with the WhatsMyName dataset.' },
                });
                if (String(hNode.id) !== String(seed.id)) {
                    await ctx.graph!.createEdge!({ from: String(seed.id), to: String(hNode.id), label: 'uses handle' });
                    anchorId = String(hNode.id);
                    handles++;
                }
            }

            const seen = new Set<string>();
            for (const f of hits) {
                if (ctx.signal?.aborted) break;
                const key = `${f.name} ${f.profile_url}`;
                if (seen.has(key)) continue;
                seen.add(key);
                const node = await ctx.graph!.createNode!({
                    type: 'identity.account',
                    data: {
                        username: handle,
                        platform: f.name,
                        profile_url: f.profile_url,
                    },
                });
                if (String(node.id) !== anchorId) {
                    await ctx.graph!.createEdge!({ from: anchorId, to: String(node.id), label: 'same handle' });
                    accounts++;
                }
            }

            found += hits.length;
            checked += nodeChecked;
            blocked += nodeBlocked;
            processed++;
            lastHits = hits.length;
            lastChecked = nodeChecked;
        }

        const skipped = noHandle + badHandle + notFound;
        const skipNote = skipped
            ? ` (${skipped} node(s) skipped: ${noHandle} without a handle, ${badHandle} unsafe, ${notFound} not found)`
            : '';
        const blockedNote = blocked
            ? ` — ${blocked} more looked like a hit but failed independent verification (antibot page or unreliable site) and were not added`
            : '';
        return {
            summary:
                processed === 1
                    ? `"${lastHandle}" found on ${lastHits} site(s) of ${lastChecked} checked${skipNote}${blockedNote}`
                    : `${found} account(s) found across ${processed} handle(s)${skipNote}${blockedNote}`,
            counts: {
                found,
                handles,
                accounts,
                checked,
                no_handle: noHandle,
                bad_handle: badHandle,
                not_found: notFound,
                blocked,
            },
        };
    },
});

// One file, one plugin (room to grow into an OSINT pack later), mirroring the chaos pack model.
export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.whatsmyname',
    content_type: 'vineyard:pluginpack',
    name: 'WhatsMyName',
    version: '2.2.2',
    description:
        'Username enumeration across ~700 sites using the WhatsMyName dataset (https://github.com/WebBreacher/WhatsMyName, CC-BY-SA-4.0). Desktop only.',
    plugins: [whatsmyname],
});

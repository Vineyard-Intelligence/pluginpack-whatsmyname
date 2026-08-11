// Functional test harness for pluginpack-whatsmyname/dist/pack.mjs.
// Run: node test-plugin.mjs
import pack from "./dist/pack.mjs";

const say = typeof console !== "undefined" ? (m) => console.log(m) : print;
const die = () => (typeof process !== "undefined" ? process.exit(1) : quit(1));
if (typeof console === "undefined") {
  globalThis.console = { log: print, warn: print, error: print, info: print, debug: print };
}

const [wmnPlugin] = pack.plugins;
const ok = [];
const fail = [];
function check(name, cond) {
  (cond ? ok : fail).push(name);
}

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  return {
    createdNodes,
    createdEdges,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      // Dedup on (type, key-ish identity) roughly the way the real host does for identity.handle,
      // just enough for these tests to see re-runs not double the anchor.
      const existing = createdNodes.find(
        (n) => n.type === draft.type && n.type === "identity.handle" && n.data.handle === draft.data.handle,
      );
      if (existing) return existing;
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

// siteBehaviors: Map<siteName, (acct) => { status, body }>. `probe(url, opts)` figures out which
// site + account a call is for from the URL template each test site is given (a unique path
// fragment per site keeps this unambiguous without needing to export any internals to match on).
function makeNet(dataset, siteBehaviors) {
  const probeCalls = [];
  return {
    probeCalls,
    async fetch(url) {
      if (!url.includes("wmn-data.json")) throw new Error(`unexpected fetch: ${url}`);
      return { ok: true, status: 200, async json() { return { sites: dataset }; } };
    },
    async probe(url, opts) {
      probeCalls.push({ url, opts });
      const site = dataset.find((s) => url.startsWith(s.uri_check.split("{account}")[0]));
      if (!site) throw new Error(`no matching site for probe url: ${url}`);
      const acct = url.slice(site.uri_check.split("{account}")[0].length);
      const behavior = siteBehaviors[site.name];
      const { status, body = "" } = behavior(acct);
      return { error: undefined, status, body: opts.maxBytes > 0 ? body : "" };
    },
  };
}

function makeCtx(net, graph, nodeById) {
  return {
    input: { selection: Object.keys(nodeById) },
    net,
    graph,
    signal: undefined,
    progress: { set() {} },
  };
}

// -------------------------------------------------- genuine hit: control does NOT match -> found
{
  const dataset = [
    { name: "GenuineSite", valid: true, uri_check: "https://genuine.test/u/{account}", e_code: 200 },
  ];
  const behaviors = {
    // Only the real handle resolves; anything else (the random control) 404s, exactly as a working
    // site's check should behave.
    GenuineSite: (acct) => ({ status: acct === "myhandle" ? 200 : 404 }),
  };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "myhandle" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check("genuine hit: counts.found === 1", res.counts.found === 1);
  check("genuine hit: counts.blocked === 0", res.counts.blocked === 0);
  check(
    "genuine hit: identity.account node created for GenuineSite",
    graph.createdNodes.some((n) => n.type === "identity.account" && n.data.platform === "GenuineSite"),
  );
  check("genuine hit: exactly 2 probes (real + one control)", net.probeCalls.length === 2);
  const controlUrl = net.probeCalls[1].url;
  const controlAcct = controlUrl.slice("https://genuine.test/u/".length);
  check("genuine hit: control account is same length as real handle", controlAcct.length === "myhandle".length);
  check("genuine hit: control account differs from the real handle", controlAcct !== "myhandle");
}

// -------------------------------------------------- plain miss: no extra requests fired at all
{
  const dataset = [{ name: "MissSite", valid: true, uri_check: "https://miss.test/u/{account}", e_code: 200 }];
  const behaviors = { MissSite: () => ({ status: 404 }) };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "nobody" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check("plain miss: counts.found === 0", res.counts.found === 0);
  check("plain miss: counts.blocked === 0", res.counts.blocked === 0);
  check(
    "plain miss: exactly ONE probe — no antibot scan, no differential control fired for a miss",
    net.probeCalls.length === 1,
  );
}

// -------------------------------------------------- antibot page: short-circuits before any control probe
{
  const dataset = [
    { name: "WalledSite", valid: true, uri_check: "https://walled.test/u/{account}", e_code: 200 },
  ];
  const behaviors = {
    // Every request — real or would-be control — hits the SAME Cloudflare interstitial. If the
    // antibot check works, the control probe is never even sent.
    WalledSite: () => ({ status: 200, body: "<title>Just a moment...</title> Checking your browser before access." }),
  };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "target" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check("antibot: counts.found === 0", res.counts.found === 0);
  check("antibot: counts.blocked === 1", res.counts.blocked === 1);
  check("antibot: no account node created", !graph.createdNodes.some((n) => n.type === "identity.account"));
  check("antibot: exactly ONE probe — signature check short-circuits before the differential control", net.probeCalls.length === 1);
}

// -------------------------------------------------- structurally unreliable site: both controls also match -> blocked
{
  const dataset = [
    { name: "SearchFallback", valid: true, uri_check: "https://search.test/q/{account}", e_code: 200, e_string: "results" },
  ];
  const behaviors = {
    // A generic search-results template that mentions "results" for ANY query, real or fake — the
    // Scribd-shaped false positive. Every request matches e_code/e_string identically.
    SearchFallback: () => ({ status: 200, body: "search results page" }),
  };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "someuser" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check("unreliable site: counts.found === 0", res.counts.found === 0);
  check("unreliable site: counts.blocked === 1", res.counts.blocked === 1);
  check(
    "unreliable site: THREE probes — real + first control + confirming second control",
    net.probeCalls.length === 3,
  );
}

// -------------------------------------------------- accidental collision: first control matches by luck, second doesn't -> stays found
{
  const dataset = [
    { name: "LuckySite", valid: true, uri_check: "https://lucky.test/u/{account}", e_code: 200 },
  ];
  let controlCallCount = 0;
  const behaviors = {
    LuckySite: (acct) => {
      if (acct === "realhandle") return { status: 200 };
      controlCallCount++;
      // First control call happens to "exist" (simulating an unlucky real collision); every
      // subsequent one behaves like a normal, correctly-absent account.
      return { status: controlCallCount === 1 ? 200 : 404 };
    },
  };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "realhandle" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check(
    "collision robustness: a single unlucky control does NOT suppress a genuine finding",
    res.counts.found === 1 && res.counts.blocked === 0,
  );
  check("collision robustness: THREE probes were spent confirming it", net.probeCalls.length === 3);
}

// -------------------------------------------------- e_string still required when the dataset defines one
{
  const dataset = [
    { name: "StringGated", valid: true, uri_check: "https://strings.test/u/{account}", e_code: 200, e_string: "Bio of" },
  ];
  const behaviors = {
    // Real handle's page carries the marker; the site's generic 200 for anyone else does not.
    StringGated: (acct) => ({ status: 200, body: acct === "abc" ? "Bio of abc the person" : "welcome, guest" }),
  };
  const nodeById = { h1: { id: "h1", type: "identity.handle", data: { handle: "abc" } } };
  const graph = makeGraph(nodeById);
  const net = makeNet(dataset, behaviors);
  const ctx = makeCtx(net, graph, nodeById);
  const res = await wmnPlugin.run(ctx);
  check("e_string gate: still found when the marker is present", res.counts.found === 1);
  check("e_string gate: control lacks the marker, confirms the finding (2 probes)", net.probeCalls.length === 2);
}

say(`PASS ${ok.length} / ${ok.length + fail.length}`);
if (fail.length) {
  say("FAILED:");
  fail.forEach((n) => say(`  - ${n}`));
  die();
}

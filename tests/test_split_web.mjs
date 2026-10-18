// Source-level regression tests: mocked DOM, HTTP and message delivery.
// These do not establish real-browser popup or postMessage behavior.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const sources = Object.fromEntries(["verifier", "wallet"].map(role => [role,
  readFileSync(new URL(`../split_web/${role}.js`, import.meta.url), "utf8")]));
const origins = {verifier: "http://127.0.0.1:9101", wallet: "http://127.0.0.1:9102"};

function document() {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, disabled: false, value: "", textContent: "", handlers: {},
      addEventListener(type, callback) { this.handlers[type] = callback; },
      querySelector() { return get(`${id}-button`); },
      replaceChildren() {}, append() {}, focus() {}
    });
    return elements.get(id);
  };
  return {getElementById: get, createElement: () => ({}), get};
}

function harness() {
  let now = 1_900_000_000, serial = 0, popup, wallet;
  const calls = [], messages = [];
  const verifier = {document: document(), handlers: {}};
  const runtimeDate = class extends Date { static now() { return now * 1000; } };
  const fetchFor = role => async (path, options) => {
    const body = options.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({role, path, body});
    let value;
    if (path === "/api/config") value = {
      role, synthetic: true, live_licence_status_checked: false,
      peer_origin: origins[role === "wallet" ? "verifier" : "wallet"],
      service_day: "2030-06-01", keys: [{key_id: "key-1", state: "active"}]
    };
    else if (path === "/api/login") value = {token: `${role}-token`, synthetic: true};
    else if (path === "/api/session" || path === "/api/logout") value = {};
    else if (path === "/api/requests") value = {signed_request: {payload: {challenge: {
      request_id: `request-${++serial}`, audience: "demo", service_day: "2030-06-01",
      expires_at: now + 300
    }}}};
    else if (path === "/api/review") value = {
      request_id: body.signed_request.payload.challenge.request_id, review_hash: "review-hash",
      claims: [], revealed_attributes: [], service_day: "2030-06-01", expires_at: now + 300,
      synthetic_revocation_checked: true, live_licence_status_checked: false
    };
    else if (path === "/api/decision") value = body.decision === "approve" ?
      {request_id: body.request_id, presentation: {synthetic_proof: true}} :
      {request_id: body.request_id, decision: "denied"};
    else if (path === "/api/verify") value = {
      verified: true, accepted: true, synthetic_revocation_checked: true,
      live_licence_status_checked: false
    };
    else throw new Error(`Unexpected API route: ${role} ${path}`);
    return {ok: true, status: 200, json: async () => value};
  };
  function load(role, page, window) {
    vm.runInNewContext(sources[role], {
      window, document: page.document, location: {origin: origins[role]},
      fetch: fetchFor(role), URL, Error, Date: runtimeDate
    }, {filename: `${role}.js`});
  }
  function loadWallet(reference) {
    const page = wallet = {document: document(), handlers: {}};
    const opener = {
      closed: false,
      postMessage(data, target) {
        assert.equal(target, origins.verifier);
        messages.push({from: "wallet", data});
        queueMicrotask(() => verifier.handlers.message({
          origin: origins.wallet, source: reference, data
        }));
      }
    };
    load("wallet", page, {
      opener, addEventListener(type, callback) { page.handlers[type] = callback; }
    });
    reference.deliver = data => page.handlers.message({origin: origins.verifier, source: opener, data});
  }
  function openWallet(url) {
    assert.equal(url, `${origins.wallet}/wallet.html`);
    const reference = {closed: false, focusCount: 0, reloads: 0,
      focus() { this.focusCount++; },
      postMessage(data, target) {
        assert.equal(target, origins.wallet);
        messages.push({from: "verifier", data});
        queueMicrotask(() => reference.deliver(data));
      }
    };
    Object.defineProperty(reference, "location", {
      set(value) {
        assert.equal(value, `${origins.wallet}/wallet.html`);
        reference.reloads++;
        loadWallet(reference);
      }
    });
    loadWallet(reference);
    popup = reference;
    return reference;
  }
  load("verifier", verifier, {
    addEventListener(type, callback) { verifier.handlers[type] = callback; }, open: openWallet
  });
  const flush = async () => {
    for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve));
  };
  async function event(role, id, type = "click") {
    const page = role === "verifier" ? verifier : wallet;
    await page.document.get(id).handlers[type]({preventDefault() {}});
    await flush();
  }
  return {
    calls, messages, verifier, get wallet() { return wallet; }, get popup() { return popup; },
    flush, event, advance(seconds) { now += seconds; },
    async login(role) { await event(role, "login-form", "submit"); },
    async start() {
      await flush();
      await this.login("verifier");
      await event("verifier", "new-request");
      await this.login("wallet");
    }
  };
}

for (const decision of ["approve", "deny"]) {
  test(`repeat click preserves the pending request through ${decision}`, async () => {
    const h = harness();
    await h.start();
    assert.equal(h.wallet.document.get("review-panel").hidden, false);
    await h.event("verifier", "new-request");
    assert.equal(h.calls.filter(call => call.path === "/api/requests").length, 1);
    assert.equal(h.messages.filter(item => item.data.type === "wallet-busy").length, 0);
    assert.ok(h.popup.focusCount > 0);
    await h.event("wallet", decision);
    const chosen = h.calls.find(call => call.path === "/api/decision");
    assert.equal(chosen.body.request_id, "request-1");
    assert.equal(chosen.body.decision, decision);
    const verified = h.calls.filter(call => call.path === "/api/verify");
    assert.equal(verified.length, decision === "approve" ? 1 : 0);
    if (decision === "approve") assert.equal(verified[0].body.request_id, "request-1");
    assert.equal(h.verifier.document.get("result-panel").hidden, false);
    assert.equal(h.wallet.document.get("result-panel").hidden, false);
    assert.equal(h.messages.filter(item => item.data.type === "wallet-proof").length,
      decision === "approve" ? 1 : 0);
    // A completed choice allows the next request without requiring another login.
    await h.event("verifier", "new-request");
    assert.equal(h.calls.filter(call => call.path === "/api/requests").length, 2);
    assert.equal(h.wallet.document.get("review-panel").hidden, false);
    assert.equal(h.popup.reloads, 0);
  });
}

test("a closed Wallet permits a new request", async () => {
  const h = harness();
  await h.start();
  const previousPopup = h.popup;
  previousPopup.closed = true;
  await h.event("verifier", "new-request");
  assert.notEqual(h.popup, previousPopup);
  await h.login("wallet");
  await h.event("wallet", "approve");
  assert.equal(h.calls.find(call => call.path === "/api/verify").body.request_id, "request-2");
});

test("an expired request resets the Wallet before starting again", async () => {
  const h = harness();
  await h.start();
  h.advance(301);
  await h.event("verifier", "new-request");
  assert.equal(h.messages.filter(item => item.data.type === "wallet-busy").length, 0);
  assert.equal(h.popup.reloads, 1);
  await h.login("wallet");
  await h.event("wallet", "approve");
  assert.equal(h.calls.find(call => call.path === "/api/verify").body.request_id, "request-2");
  assert.equal(h.messages.filter(item => item.data.type === "wallet-busy").length, 0);
});

test("logging out of the reception abandons its old Wallet request", async () => {
  const h = harness();
  await h.start();
  await h.event("verifier", "logout");
  await h.login("verifier");
  await h.event("verifier", "new-request");
  assert.equal(h.messages.filter(item => item.data.type === "wallet-busy").length, 0);
  assert.equal(h.popup.reloads, 1);
  await h.login("wallet");
  await h.event("wallet", "deny");
  assert.equal(h.calls.find(call => call.path === "/api/decision").body.request_id, "request-2");
  assert.equal(h.verifier.document.get("result-panel").hidden, false);
});

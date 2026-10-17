"use strict";

const PROTOCOL = "zk-license-split-v1";
const el = id => document.getElementById(id);
const errors = {
  invalid_login: "ログインコードが一致しません。検証者プロセスの端末を確認してください。",
  authentication_required: "ログインの期限が切れました。もう一度ログインしてください。",
  rate_limited: "操作が続いたため、少し待ってからやり直してください。",
  request_unavailable: "この要求は利用できません。新しい要求を作ってください。",
  request_expired: "要求の期限が切れました。新しい要求を作ってください。",
  request_expired_or_clock_invalid: "要求の期限が切れました。新しい要求を作ってください。",
  stale_registry_request: "公開状態が更新されました。新しい要求を作ってください。",
  already_used: "この要求は使用済みです。新しい要求を作ってください。",
  invalid_proof: "証明を確認できませんでした。新しい要求でやり直してください。",
  key_not_trusted: "この発行鍵は現在利用できません。鍵の状態を確認してください。"
};

let config = null;
let token = "";
let walletWindow = null;
let walletReady = false;
let current = null;
let verifying = false;
let creating = false;
let refreshing = false;

function message(value) { el("message").textContent = value; }
function describeError(error) { return error instanceof Error ? error.message : "操作を完了できませんでした。"; }

async function api(path, body) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const options = {credentials: "omit", cache: "no-store", headers};
  if (body !== undefined) {
    options.method = "POST";
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    const error = new Error(errors[value.error] || "操作を完了できませんでした。新しい要求でやり直してください。");
    error.code = value.error;
    throw error;
  }
  return value;
}

function requirePeerOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port ||
      url.origin !== value || url.origin === location.origin || url.username || url.password ||
      url.search || url.hash) throw new Error("接続先の設定を確認できませんでした。");
  return url.origin;
}

async function refreshConfig() {
  const value = await api("/api/config");
  if (value.role !== "verifier" || value.synthetic !== true || value.live_licence_status_checked !== false ||
      !Array.isArray(value.keys)) throw new Error("検証者の設定を確認できませんでした。");
  value.peer_origin = requirePeerOrigin(value.peer_origin);
  if (config && value.peer_origin !== config.peer_origin) throw new Error("接続先の設定が変わりました。画面を開き直してください。");
  const previous = el("key-id").value;
  const wasActive = config && config.keys.some(key => key.key_id === previous && key.state === "active");
  const keys = value.keys.filter(item => item && typeof item.key_id === "string" &&
    (item.state === "active" || item.state === "verify_only"));
  value.keys = keys;
  config = value;
  el("service-day").textContent = value.service_day;
  el("key-id").replaceChildren();
  for (const key of keys) {
    const option = document.createElement("option");
    option.value = key.key_id;
    option.textContent = `${key.key_id} (${key.state === "active" ? "現在の鍵" : "併存中の旧鍵"})`;
    el("key-id").append(option);
  }
  const previousKey = keys.find(key => key.key_id === previous);
  const active = keys.find(key => key.state === "active");
  if (previousKey && !(wasActive && previousKey.state !== "active" && active)) el("key-id").value = previous;
  else if (active) el("key-id").value = active.key_id;
  el("new-request").disabled = !keys.length || creating || refreshing;
}

function showLogin() {
  token = "";
  current = null;
  verifying = false;
  el("login-panel").hidden = false;
  el("work-panel").hidden = true;
  el("request-panel").hidden = true;
  el("result-panel").hidden = true;
}

function showWork() {
  el("login-panel").hidden = true;
  el("work-panel").hidden = false;
}

function result(title, detail, verified = false) {
  current = null;
  el("request-panel").hidden = true;
  el("result-title").textContent = title;
  el("result-description").textContent = detail;
  el("result-limits").textContent = verified ?
    "模擬資格情報の条件と模擬失効情報を確認しました。実免許証の状態・実在人物の本人性は確認していません。" :
    "証明の検証は行っていません。実免許証の状態・実在人物の本人性も確認していません。";
  el("result-panel").hidden = false;
  el("result-panel").focus();
}

function deliverRequest() {
  if (!token || !current || !walletReady || !walletWindow || walletWindow.closed) return;
  walletWindow.postMessage({protocol: PROTOCOL, type: "wallet-request",
    request_id: current.id, signed_request: current.signed}, config.peer_origin);
}

async function verifyPresentation(value) {
  if (verifying || !current || !token || value.request_id !== current.id ||
      !value.presentation || typeof value.presentation !== "object" || Array.isArray(value.presentation)) return;
  verifying = true;
  const requestId = current.id;
  message("届いた証明を確認しています…");
  try {
    const checked = await api("/api/verify", {
      request_id: current.id, presentation: value.presentation
    });
    if (checked.verified !== true || checked.accepted !== true ||
        checked.synthetic_revocation_checked !== true || checked.live_licence_status_checked !== false) {
      throw new Error("検証結果を確認できませんでした。新しい要求でやり直してください。");
    }
    if (!token || !current || current.id !== requestId) return;
    message("");
    result("模擬資格情報の条件を確認しました", "発行者の署名、要求した条件、模擬失効情報を確認し、この要求を使用済みにしました。", true);
  } catch (error) {
    if (!token || !current || current.id !== requestId) return;
    message(describeError(error));
    current = null;
    el("request-panel").hidden = true;
  } finally {
    verifying = false;
  }
}

window.addEventListener("message", event => {
  if (!config || event.origin !== config.peer_origin || !walletWindow || event.source !== walletWindow) return;
  const value = event.data;
  if (!value || typeof value !== "object" || value.protocol !== PROTOCOL) return;
  if (value.type === "wallet-ready") {
    walletReady = true;
    deliverRequest();
    return;
  }
  if (!current || value.request_id !== current.id || !token) return;
  if (value.type === "wallet-proof") void verifyPresentation(value);
  else if (value.type === "wallet-denied") {
    message("");
    result("今回は共有されませんでした", "ウォレットで同意が拒否されました。証明は届いていません。必要なら新しい要求を作ってください。");
  } else if (value.type === "wallet-error" || value.type === "wallet-busy") {
    message("ウォレットで要求を処理できませんでした。ウォレット画面を確認し、新しい要求を作ってください。");
    current = null;
    el("request-panel").hidden = true;
  }
});

el("login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = el("login-form").querySelector("button");
  button.disabled = true;
  message("");
  try {
    const code = el("login-code").value;
    el("login-code").value = "";
    const login = await api("/api/login", {code});
    if (!login.token || login.synthetic !== true) throw new Error("ログイン結果を確認できませんでした。");
    token = login.token;
    await api("/api/session");
    showWork();
    el("new-request").focus();
  } catch (error) { message(describeError(error)); }
  finally { button.disabled = false; }
});

el("logout").addEventListener("click", async () => {
  el("logout").disabled = true;
  try { await api("/api/logout", {}); }
  catch (error) { message(describeError(error)); }
  finally { showLogin(); el("logout").disabled = false; el("login-code").focus(); }
});

el("refresh-keys").addEventListener("click", async () => {
  if (creating || refreshing) return;
  refreshing = true;
  const button = el("refresh-keys");
  button.disabled = true;
  el("new-request").disabled = true;
  message("");
  try { await refreshConfig(); }
  catch (error) { message(describeError(error)); }
  finally {
    refreshing = false;
    button.disabled = false;
    el("new-request").disabled = !config || !config.keys.some(key => key.state === "active" || key.state === "verify_only");
  }
});

el("new-request").addEventListener("click", async () => {
  if (!config || !token || verifying || creating || refreshing) return;
  const activeToken = token;
  // Opening in the click handler avoids the browser's popup blocker.
  if (!walletWindow || walletWindow.closed) {
    walletReady = false;
    walletWindow = window.open(`${config.peer_origin}/wallet.html`, "_blank", "width=620,height=820");
  } else walletWindow.focus();
  if (!walletWindow) { message("ウォレット画面を開けませんでした。ポップアップの設定を確認してください。"); return; }
  const button = el("new-request");
  creating = true;
  button.disabled = true;
  el("refresh-keys").disabled = true;
  message("");
  current = null;
  el("request-panel").hidden = true;
  el("result-panel").hidden = true;
  try {
    await refreshConfig();
    if (token !== activeToken) return;
    const keyId = el("key-id").value;
    if (!keyId) throw new Error("利用できる発行鍵がありません。");
    const created = await api("/api/requests", {key_id: keyId});
    if (token !== activeToken) return;
    const signed = created.signed_request;
    const challenge = signed && signed.payload && signed.payload.challenge;
    if (!challenge || typeof challenge.request_id !== "string") throw new Error("要求を確認できませんでした。");
    current = {id: challenge.request_id, signed};
    el("request-id").textContent = challenge.request_id;
    el("audience").textContent = challenge.audience;
    el("request-day").textContent = challenge.service_day;
    el("request-expires").textContent = new Date(challenge.expires_at * 1000).toLocaleString("ja-JP");
    el("request-panel").hidden = false;
    deliverRequest();
  } catch (error) { message(describeError(error)); }
  finally {
    creating = false;
    button.disabled = !config.keys.some(key => key.state === "active" || key.state === "verify_only");
    el("refresh-keys").disabled = false;
  }
});

refreshConfig().catch(error => { message(describeError(error)); el("new-request").disabled = true; });

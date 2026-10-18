"use strict";

const PROTOCOL = "zk-license-split-v1";
const el = id => document.getElementById(id);
const errors = {
  session_capacity: "現在ログインできません。少し待ってから、もう一度ログインしてください。",
  invalid_login: "コードが一致しません。Wallet 用のログインコードを確認してください。",
  authentication_required: "ログインが必要です。もう一度ログインしてください。",
  rate_limited: "操作回数の上限に達しました。少し待ってからやり直してください。",
  stale_registry_request: "デモのデータが更新されました。受付画面からやり直してください。",
  request_expired_or_clock_invalid: "この確認内容は利用できません。受付画面からやり直してください。",
  unauthenticated_request: "送信元を確認できませんでした。受付画面からやり直してください。",
  unsupported_disclosure_policy: "この確認内容には対応していません。受付画面からやり直してください。",
  wallet_credential_unavailable: "この確認に使えるサンプルデータがありません。デモを準備した人に確認してください。",
  credential_revoked: "このサンプルデータは現在使えません。デモを準備した人に確認してください。",
  matching_wallet_review_required: "表示した内容と一致しません。受付画面からやり直してください。",
  request_changed_or_decided: "内容が変更されたか、すでに操作を終えています。受付画面からやり直してください。"
};

let config = null;
let token = "";
let pending = null;
let reviewing = false;
let deciding = false;

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
  const response = await fetch(path, options).catch(() => {
    throw new Error("デモに接続できませんでした。デモが起動しているか確認し、もう一度操作してください。");
  });
  const value = await response.json().catch(() => {
    throw new Error("デモからの応答を読み取れませんでした。画面を開き直してください。");
  });
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    const error = new Error(errors[value.error] || "操作を完了できませんでした。画面を開き直して、もう一度お試しください。");
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

function notifyVerifier(type, requestId, presentation) {
  if (!config || !window.opener || window.opener.closed) return false;
  const value = {protocol: PROTOCOL, type, request_id: requestId};
  if (type === "wallet-proof") value.presentation = presentation;
  try {
    window.opener.postMessage(value, config.peer_origin);
    return true;
  } catch {
    return false;
  }
}

function showLogin() {
  token = "";
  el("login-panel").hidden = false;
  el("work-panel").hidden = true;
  el("review-panel").hidden = true;
}

function showWork() {
  el("login-panel").hidden = true;
  el("work-panel").hidden = false;
  el("waiting-panel").hidden = !!pending;
}

function displayReview(review) {
  el("audience").textContent = review.audience;
  el("device-binding").textContent = review.device_binding;
  el("service-day").textContent = `${review.service_day}（デモ用の日付）`;
  el("expires").textContent = new Date(review.expires_at * 1000).toLocaleString("ja-JP");
  el("issuer-key").textContent = review.issuer_key;
  el("key-state").textContent = review.key_state === "active" ? "現在の発行鍵" : "更新前の鍵（確認用）";
  const claimLabels = {
    "can_drive_ordinary >= 1": "サンプルデータに普通車の運転資格が登録されていること",
    [`valid_until >= ${review.service_day}`]: "登録された有効期限が利用予定日以降であること"
  };
  el("claims").replaceChildren();
  for (const claim of review.claims) {
    const item = document.createElement("li");
    item.textContent = claimLabels[claim] || claim;
    el("claims").append(item);
  }
  el("revealed-attributes").textContent = review.revealed_attributes.length ?
    review.revealed_attributes.join("、") : "ありません。氏名・住所・生年月日・免許証番号・有効期限の具体的な日付は証明に含めません。";
  el("waiting-panel").hidden = true;
  el("result-panel").hidden = true;
  el("review-panel").hidden = false;
  el("approve").focus();
}

function clearPending() {
  pending = null;
  el("review-panel").hidden = true;
  el("waiting-panel").hidden = false;
}

function showResult(title, detail) {
  clearPending();
  el("result-title").textContent = title;
  el("result-description").textContent = detail;
  el("result-panel").hidden = false;
  el("result-panel").focus();
}

async function reviewPending() {
  if (!token || !pending || pending.review || reviewing || deciding) return;
  const target = pending;
  reviewing = true;
  message("届いた内容を確認しています…");
  try {
    const review = await api("/api/review", {signed_request: pending.signed});
    if (pending !== target || !token) return;
    if (review.request_id !== pending.id || typeof review.review_hash !== "string" ||
        !Array.isArray(review.claims) || !Array.isArray(review.revealed_attributes) ||
        review.synthetic_revocation_checked !== true || review.live_licence_status_checked !== false) {
      throw new Error("確認結果を表示できませんでした。");
    }
    pending.review = review;
    message("");
    showWork();
    displayReview(review);
  } catch (error) {
    if (pending !== target) return;
    message(describeError(error));
    if (error.code !== "authentication_required") {
      const requestId = pending && pending.id;
      clearPending();
      if (requestId) notifyVerifier("wallet-error", requestId);
    }
  } finally { reviewing = false; }
}

window.addEventListener("message", event => {
  if (!config || event.origin !== config.peer_origin || event.source !== window.opener) return;
  const value = event.data;
  if (!value || typeof value !== "object" || value.protocol !== PROTOCOL || value.type !== "wallet-request") return;
  const signed = value.signed_request;
  const challenge = signed && signed.payload && signed.payload.challenge;
  if (!challenge || typeof challenge.request_id !== "string" || value.request_id !== challenge.request_id) return;
  if (pending) {
    if (pending.id !== value.request_id) notifyVerifier("wallet-busy", value.request_id);
    return;
  }
  pending = {id: value.request_id, signed, review: null};
  el("result-panel").hidden = true;
  if (!token) message("受付から確認内容が届きました。ログインすると内容を確認できます。");
  else void reviewPending();
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
    if (pending) await reviewPending();
  } catch (error) { message(describeError(error)); }
  finally { button.disabled = false; }
});

el("logout").addEventListener("click", async () => {
  if (deciding) return;
  el("logout").disabled = true;
  const requestId = pending && pending.id;
  try { await api("/api/logout", {}); }
  catch (error) { message(describeError(error)); }
  finally {
    if (requestId) notifyVerifier("wallet-error", requestId);
    clearPending();
    el("result-panel").hidden = true;
    showLogin();
    el("logout").disabled = false;
    el("login-code").focus();
  }
});

async function decide(decision) {
  if (!token || !pending || !pending.review || deciding) return;
  deciding = true;
  el("approve").disabled = true;
  el("deny").disabled = true;
  el("logout").disabled = true;
  message(decision === "approve" ? "共有する証明を準備しています…" : "選択を保存しています…");
  const requestId = pending.id;
  try {
    const result = await api("/api/decision", {
      request_id: requestId, review_hash: pending.review.review_hash, decision
    });
    if (result.request_id !== requestId) throw new Error("処理結果を確認できませんでした。");
    if (decision === "approve") {
      if (!result.presentation || typeof result.presentation !== "object" || Array.isArray(result.presentation)) {
        throw new Error("証明を確認できませんでした。");
      }
      const sent = notifyVerifier("wallet-proof", requestId, result.presentation);
      showResult(sent ? "証明を送信しました" : "証明を送信できませんでした", sent ?
        "確認結果は受付画面をご覧ください。結果が表示されない場合は、受付画面からやり直してください。" :
        "同意は保存されましたが、証明を送信できませんでした。受付画面を開き直して、もう一度始めてください。");
    } else {
      if (result.decision !== "denied") throw new Error("選択を保存できたか確認できませんでした。");
      const sent = notifyVerifier("wallet-denied", requestId);
      showResult("今回は共有しませんでした", sent ?
        "共有しない選択を受付画面へ通知しました。証明は作成・送信していません。" :
        "共有しない選択を保存しました。受付画面へ通知できませんでした。証明は作成・送信していません。");
    }
    message("");
  } catch (error) {
    message(describeError(error));
    notifyVerifier("wallet-error", requestId);
    clearPending();
  } finally {
    deciding = false;
    el("approve").disabled = false;
    el("deny").disabled = false;
    el("logout").disabled = false;
  }
}

el("approve").addEventListener("click", () => void decide("approve"));
el("deny").addEventListener("click", () => void decide("deny"));

api("/api/config").then(value => {
  if (value.role !== "wallet" || value.synthetic !== true || value.live_licence_status_checked !== false) {
    throw new Error("Wallet の設定を確認できませんでした。");
  }
  value.peer_origin = requirePeerOrigin(value.peer_origin);
  config = value;
  if (window.opener && !window.opener.closed) {
    window.opener.postMessage({protocol: PROTOCOL, type: "wallet-ready"}, config.peer_origin);
  }
}).catch(error => { message(describeError(error)); });

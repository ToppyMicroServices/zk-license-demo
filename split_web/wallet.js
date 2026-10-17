"use strict";

const PROTOCOL = "zk-license-split-v1";
const el = id => document.getElementById(id);
const errors = {
  invalid_login: "ログインコードが一致しません。ウォレットプロセスの端末を確認してください。",
  authentication_required: "ログインの期限が切れました。もう一度ログインしてください。",
  rate_limited: "操作が続いたため、少し待ってからやり直してください。",
  stale_registry_request: "公開状態が更新されました。検証者に新しい要求を作ってもらってください。",
  request_expired_or_clock_invalid: "要求の期限が切れました。検証者に新しい要求を作ってもらってください。",
  unauthenticated_request: "要求の出所を確認できませんでした。共有しないでください。",
  unsupported_disclosure_policy: "この要求は対応していない内容です。共有しないでください。",
  wallet_credential_unavailable: "この発行鍵に対応する模擬資格情報がありません。発行と取込みをやり直してください。",
  credential_revoked: "この模擬資格情報は失効しています。共有できません。",
  matching_wallet_review_required: "確認済みの要求と一致しません。新しい要求からやり直してください。",
  request_changed_or_decided: "この要求は変更済みか、すでに選択済みです。新しい要求からやり直してください。"
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
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    const error = new Error(errors[value.error] || "要求を処理できませんでした。新しい要求でやり直してください。");
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
  el("service-day").textContent = `${review.service_day}（説明用の日付）`;
  el("expires").textContent = new Date(review.expires_at * 1000).toLocaleString("ja-JP");
  el("issuer-key").textContent = review.issuer_key;
  el("key-state").textContent = review.key_state === "active" ? "現在の鍵" : "併存中の旧鍵";
  el("claims").replaceChildren();
  for (const claim of review.claims) {
    const item = document.createElement("li");
    item.textContent = claim;
    el("claims").append(item);
  }
  el("revealed-attributes").textContent = review.revealed_attributes.length ?
    review.revealed_attributes.join("、") : "なし。氏名・住所・生年月日・免許証番号・有効期限の具体的な日付は渡しません。";
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
  message("要求の出所と内容を確認しています…");
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
  if (!token) message("要求を受け取りました。ログイン後に内容を確認します。");
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
  message(decision === "approve" ? "証明を作成しています…" : "拒否を記録しています…");
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
        "この要求の証明を検証者画面へ送りました。受理結果は検証者画面で確認してください。" :
        "この要求への同意は確定しましたが、検証者画面が利用できず証明を送れませんでした。新しい要求からやり直してください。");
    } else {
      if (result.decision !== "denied") throw new Error("拒否の結果を確認できませんでした。");
      const sent = notifyVerifier("wallet-denied", requestId);
      showResult("今回は共有しませんでした", sent ?
        "この要求への拒否を記録し、検証者画面へ伝えました。証明は作成・送信していません。" :
        "この要求への拒否を記録しました。検証者画面が利用できず通知できませんでした。証明は作成・送信していません。");
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
    throw new Error("ウォレットの設定を確認できませんでした。");
  }
  value.peer_origin = requirePeerOrigin(value.peer_origin);
  config = value;
  if (window.opener && !window.opener.closed) {
    window.opener.postMessage({protocol: PROTOCOL, type: "wallet-ready"}, config.peer_origin);
  }
}).catch(error => { message(describeError(error)); });

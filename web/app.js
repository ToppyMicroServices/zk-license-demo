"use strict";
const el = id => document.getElementById(id);
let csrf = "", currentRequest = null;
const errors = {
  invalid_login: "ログインコードが一致しません。起動した端末の表示を確認してください。",
  authentication_required: "ログインが必要です。セッションの期限が切れた場合は、もう一度ログインしてください。",
  rate_limited: "操作が続いたため、少し待ってからやり直してください。",
  request_unavailable: "この要求は利用できません。期限切れの場合は新しい要求を受け取ってください。",
  request_expired: "要求の期限が切れています。新しい要求を受け取ってください。",
  already_used: "この要求は検証済みです。同じ証明を再送することはできません。",
  consent_required: "この要求への同意が記録されていません。",
  request_changed: "表示した要求と一致しません。新しい要求を受け取ってください。",
  invalid_proof: "証明を検証できませんでした。",
  csrf_failed: "操作の確認に失敗しました。画面を再読み込みしてログイン状態を確認してください。"
};
async function api(path, body) {
  const options = {credentials: "same-origin", cache: "no-store"};
  if (body !== undefined) Object.assign(options, {method: "POST", headers: {
    "Content-Type": "application/json", "X-CSRF-Token": csrf
  }, body: JSON.stringify(body)});
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(errors[value.error] || "操作を完了できませんでした。新しい要求でやり直してください。");
  }
  return value;
}
function step(name) {
  for (const item of ["login", "consent", "result"]) {
    if (item === name) el(`step-${item}`).setAttribute("aria-current", "step");
    else el(`step-${item}`).removeAttribute("aria-current");
  }
}
function showLogin() {
  csrf = ""; currentRequest = null;
  el("login-panel").hidden = false;
  el("wallet-panel").hidden = true;
  el("request-panel").hidden = true;
  el("result-panel").hidden = true;
  el("proof-json").textContent = "";
  step("login");
}
function showWallet(session) {
  csrf = session.csrf;
  el("login-panel").hidden = true;
  el("wallet-panel").hidden = false;
  step("consent");
}
async function perform(action) {
  el("message").textContent = "";
  const buttons = [...document.querySelectorAll("button")];
  buttons.forEach(button => {button.disabled = true;});
  try { await action(); }
  catch (error) { el("message").textContent = error.message; }
  finally { buttons.forEach(button => {button.disabled = false;}); }
}
el("login-form").addEventListener("submit", event => {
  event.preventDefault();
  perform(async () => {
    const code = el("login-code").value;
    el("login-code").value = "";
    showWallet(await api("/api/login", {code}));
    el("new-request").focus();
  });
});
el("logout").addEventListener("click", () => perform(async () => {
  await api("/api/logout", {}); showLogin(); el("login-code").focus();
}));
el("new-request").addEventListener("click", () => perform(async () => {
  currentRequest = await api("/api/requests", {});
  el("verifier").textContent = `${currentRequest.verifier_name} (${currentRequest.audience})`;
  el("purpose").textContent = currentRequest.purpose;
  el("service-day").textContent = `${currentRequest.service_day}（説明用の日付）`;
  el("expires").textContent = new Date(currentRequest.expires_at * 1000).toLocaleString("ja-JP");
  el("request-json").textContent = JSON.stringify(currentRequest, null, 2);
  el("request-panel").hidden = false;
  el("result-panel").hidden = true;
  el("proof-json").textContent = "";
  step("consent");
}));
function result(title, description, limitation) {
  el("result-title").textContent = title;
  el("result-description").textContent = description;
  el("result-limit").textContent = limitation;
  el("request-panel").hidden = true;
  el("result-panel").hidden = false;
  step("result");
  el("result-panel").focus();
}
el("deny").addEventListener("click", () => perform(async () => {
  await api(`/api/requests/${currentRequest.request_id}/consent`, {
    decision: "deny", request_hash: currentRequest.request_hash
  });
  el("proof-details").hidden = true;
  result("今回は共有しませんでした", "同意しないという選択を記録しました。この要求の証明は作成・送信していません。", "別の要求を受け取った場合は、改めて内容を確認して選べます。");
}));
el("approve").addEventListener("click", () => perform(async () => {
  await api(`/api/requests/${currentRequest.request_id}/consent`, {
    decision: "approve", request_hash: currentRequest.request_hash
  });
  // Hide the controls once the irreversible decision has been recorded.
  el("request-panel").hidden = true;
  el("message").textContent = "証明を作成し、確認しています…";
  const envelope = await api(`/api/requests/${currentRequest.request_id}/presentation`, {});
  const verified = await api("/api/verify", envelope);
  if (verified.verified !== true) throw new Error("検証成功を確認できませんでした。");
  el("message").textContent = "";
  el("proof-json").textContent = JSON.stringify(envelope, null, 2);
  el("proof-details").hidden = false;
  result("模擬資格情報の条件を確認しました", "発行者の署名に基づく2つの条件を検証し、この要求を使用済みにしました。", "実免許証の有効性、停止・取消し、実在人物の本人性は確認していません。");
}));
api("/api/session").then(showWallet).catch(() => showLogin());

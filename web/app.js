"use strict";
const el = id => document.getElementById(id);
let csrf = "", currentRequest = null;
const errors = {
  session_capacity: "現在ログインできません。少し待ってから、もう一度ログインしてください。",
  invalid_login: "コードが一致しません。デモの起動時に表示されたログインコードを確認してください。",
  authentication_required: "ログインが必要です。もう一度ログインしてください。",
  rate_limited: "操作回数の上限に達しました。少し待ってからやり直してください。",
  request_unavailable: "この確認内容は利用できません。「確認内容を受け取る」からやり直してください。",
  request_expired: "操作期限が切れました。「確認内容を受け取る」からやり直してください。",
  already_used: "この確認内容は使用済みです。「確認内容を受け取る」からやり直してください。",
  consent_required: "共有するには、内容を確認して同意してください。",
  request_changed: "表示した内容と一致しません。新しい確認内容を受け取ってください。",
  invalid_proof: "証明を確認できませんでした。「確認内容を受け取る」からやり直してください。",
  csrf_failed: "操作の確認に失敗しました。画面を再読み込みしてログイン状態を確認してください。"
};
async function api(path, body) {
  const options = {credentials: "same-origin", cache: "no-store"};
  if (body !== undefined) Object.assign(options, {method: "POST", headers: {
    "Content-Type": "application/json", "X-CSRF-Token": csrf
  }, body: JSON.stringify(body)});
  const response = await fetch(path, options).catch(() => {
    throw new Error("デモに接続できませんでした。デモが起動しているか確認し、もう一度操作してください。");
  });
  const value = await response.json().catch(() => {
    throw new Error("デモからの応答を読み取れませんでした。画面を開き直してください。");
  });
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(errors[value.error] || "操作を完了できませんでした。画面を開き直して、もう一度お試しください。");
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
  el("service-day").textContent = `${currentRequest.service_day}（デモ用の日付）`;
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
  result("今回は共有しませんでした", "証明は作成・送信していません。", "もう一度試す場合は、「確認内容を受け取る」を押してください。");
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
  if (verified.verified !== true) throw new Error("確認結果を受け取れませんでした。「確認内容を受け取る」からやり直してください。");
  el("message").textContent = "";
  el("proof-json").textContent = JSON.stringify(envelope, null, 2);
  el("proof-details").hidden = false;
  result("条件の確認が完了しました", "サンプルデータが、運転資格と有効期限の条件を満たしています。", "サンプルデータでの確認結果です。");
}));
api("/api/session").then(showWallet).catch(() => showLogin());

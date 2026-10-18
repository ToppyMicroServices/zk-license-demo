#!/usr/bin/env python3
"""Run a real local ZK demo, or independently verify its public presentation."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from html import escape
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import time

from request_store import Challenge, Rejected, RequestStore
from zk_license import (PublicTrust, issue_demo, make_issuer, make_presentation,
                        verify_presentation)


def read_json(path: str | Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def bad_constant(value):
        raise ValueError("Non-finite JSON number")
    raw = Path(path).read_bytes()
    if len(raw) > 1_048_576:
        raise ValueError("JSON file exceeds 1 MiB")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    if not isinstance(value, dict):
        raise ValueError("A JSON object is required")
    return value


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
                    encoding="utf-8")
    path.chmod(0o600)


def render_report(path: Path, result: dict) -> None:
    # Only synthetic attributes, which are deliberately shown on the holder side.
    # This explanatory report is NOT the verifier's storage or a production wallet.
    html = """<!doctype html><html lang="ja"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Toppy | 条件確認の実行結果</title>
<style>body{font:17px/1.8 system-ui,sans-serif;max-width:1000px;margin:3rem auto;padding:0 1.5rem}
h1{font-size:2rem;line-height:1.4}section{border:1px solid;padding:1.2rem;margin:1.5rem 0}
pre{white-space:pre-wrap;word-break:break-word;font-size:13px}small{display:block}</style>
<p>TOPPY / PRIVACY ENGINEERING / SYNTHETIC DEMO</p>
<h1>条件確認の実行結果</h1>
<p>サンプルデータを使い、このパソコンでAnonCredsによる証明の作成・確認を行った結果です。
実際の免許証が有効かどうかの確認や、本人確認には利用できません。</p>
<section><h2>① 利用者のサンプルデータ</h2><p>説明のために、Wallet が保持するサンプルデータを表示しています。
これらの値は証明に含めません。</p><pre>HOLDER</pre></section>
<section><h2>② 確認条件と実行結果</h2><p>確認した条件は、サンプルデータに普通車の運転資格が登録されていることと、
登録された有効期限が利用予定日以降であることです。あらかじめ信頼したデモの発行元の署名に基づきます。</p><pre>RESULT</pre></section>
<section><h2>③ 受付に渡る情報</h2><p>以下は共有する情報の要約です。
実際のproof-envelope.jsonには証明・発行者定義の識別子・確認IDが入ります。
受付は別途、利用予定日・宛先・セッション・nonce・操作期限・使用済み状態を管理します。
これらの識別子や確認記録は受付に残ります。</p><pre>PUBLIC</pre></section>
<small>このレポートは、他社の実装を再現・評価したものではありません。
このHTMLにはスクリプト、外部画像、解析タグ、アップロード機能はありません。</small></html>"""
    html = html.replace("HOLDER", escape(json.dumps(result["synthetic_holder_data"], ensure_ascii=False, indent=2)))
    html = html.replace("RESULT", escape(json.dumps(result["measurements"], ensure_ascii=False, indent=2)))
    html = html.replace("PUBLIC", escape(json.dumps(result["public_summary"], ensure_ascii=False, indent=2)))
    path.write_text(html, encoding="utf-8")


def run(out: Path, service_day: str) -> None:
    if out.exists() and any(out.iterdir()):
        raise ValueError("Output directory must be empty; refusing to overwrite verifier state")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)
    start = time.perf_counter()
    issuer = make_issuer()
    setup_ms = (time.perf_counter() - start) * 1000
    holder = issue_demo(issuer)
    challenge = Challenge.new(audience="https://rental.example", session=secrets.token_hex(16),
                              service_day=service_day)
    start = time.perf_counter()
    presentation = make_presentation(holder, challenge, issuer.trust)
    proof_ms = (time.perf_counter() - start) * 1000
    # A fresh, separate state file lets a second CLI process verify independently.
    for name in ("demo-state.sqlite3", "verifier-state.sqlite3"):
        RequestStore(out / name).add(challenge)
        os.chmod(out / name, 0o600)
    store = RequestStore(out / "demo-state.sqlite3")
    start = time.perf_counter()
    store.consume(challenge.request_id, audience=challenge.audience, session=challenge.session,
                  verify=lambda req: verify_presentation(presentation, req, issuer.trust))
    verify_ms = (time.perf_counter() - start) * 1000
    try:
        store.consume(challenge.request_id, audience=challenge.audience, session=challenge.session,
                      verify=lambda req: verify_presentation(presentation, req, issuer.trust))
        raise RuntimeError("Replay was accepted")
    except Rejected as exc:
        if str(exc) != "already_used":
            raise
    envelope = {"request_id": challenge.request_id, "presentation": presentation}
    write_json(out / "proof-envelope.json", envelope)
    write_json(out / "trust.json", issuer.trust.to_dict())
    write_json(out / "request.json", asdict(challenge))
    report = {
        "kind": "SYNTHETIC EDUCATIONAL REPORT -- NOT VERIFIER STORAGE",
        "synthetic_holder_data": holder.synthetic_attributes,
        "public_summary": {"verified_predicates": challenge.proof_request(issuer.trust.cred_def_id)["requested_predicates"],
                           "identifiers": presentation["identifiers"],
                           "disclosed_attribute_values": {}},
        "measurements": {"accepted": True, "replay": "rejected: already_used",
                         "service_day": service_day,
                         "setup_ms": round(setup_ms, 3), "proof_ms": round(proof_ms, 3),
                         "verify_with_state_ms": round(verify_ms, 3),
                         "proof_json_bytes": len(json.dumps(presentation, separators=(",", ":")).encode()),
                         "runs": 1, "python": platform.python_version(),
                         "platform": platform.platform(), "anoncreds": version("anoncreds")},
    }
    write_json(out / "report.json", report)
    render_report(out / "report.html", report)
    print(json.dumps(report["measurements"], ensure_ascii=False, indent=2))
    print("Independent verification (within the request TTL):")
    print(f"python demo.py verify --out '{out}'")
    print("The second successful independent-verifier invocation must reject as replay.")


def verify(out: Path) -> None:
    # trust.json and verifier-state.sqlite3 are provisioned by the verifier/admin,
    # NOT received from an untrusted proof sender. All files here are synthetic.
    trust = PublicTrust.from_dict(read_json(out / "trust.json"))
    context = read_json(out / "request.json")
    envelope = read_json(out / "proof-envelope.json")
    if set(envelope) != {"request_id", "presentation"}:
        raise Rejected("unexpected_envelope_fields")
    RequestStore(out / "verifier-state.sqlite3").consume(
        envelope["request_id"], audience=context["audience"], session=context["session"],
        verify=lambda req: verify_presentation(envelope["presentation"], req, trust))
    print("ACCEPTED (synthetic credential; no real-person authentication)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--out", type=Path, default=Path("artifacts/run"))
    run_parser.add_argument("--day", default="2030-06-01", help="Illustrative service day, YYYY-MM-DD")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--out", type=Path, default=Path("artifacts/run"))
    args = parser.parse_args()
    try:
        if args.command == "run":
            run(args.out, args.day)
        else:
            verify(args.out)
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Separate, short-lived CLI processes for the synthetic lifecycle prototype."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3

import lifecycle as issuer
import split_wallet as wallet
from request_store import Rejected
from zk_license import backend


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    output = {"issuer-init", "issuer-rotate", "issuer-offer", "issuer-issue",
              "verifier-init", "verifier-reset", "verifier-request", "wallet-enroll",
              "wallet-review", "wallet-decide"}
    inputs = {"issuer-issue", "wallet-init", "wallet-pair", "wallet-enroll", "wallet-import",
              "wallet-review", "wallet-decide", "verifier-verify"}
    names = sorted(output | inputs | {"issuer-key", "issuer-revoke", "issuer-backup", "issuer-restore"})
    for name in names:
        command = commands.add_parser(name)
        command.add_argument("--store", required=True, type=Path, help="This role's private SQLite file")
        if name != "issuer-backup":
            command.add_argument("--registry", required=True, type=Path, help="Operator-provisioned public SQLite registry")
        if name in output:
            command.add_argument("--out", required=True, type=Path, help="New output file; existing files are refused")
        if name in inputs:
            command.add_argument("--input", required=True, type=Path)
        if name in ("issuer-key", "issuer-revoke", "verifier-request"):
            command.add_argument("--key-id", required=True)
        if name == "issuer-key":
            command.add_argument("--action", required=True, choices=("rollback", "retire", "revoke"))
        if name == "issuer-revoke":
            command.add_argument("--index", required=True, type=int)
        if name in ("issuer-backup", "issuer-restore"):
            command.add_argument("--backup", required=True, type=Path)
        if name == "issuer-issue":
            command.add_argument("--can-drive", type=int, default=1, choices=(0, 1))
            command.add_argument("--valid-until", default="2031-12-31")
        if name == "verifier-init":
            command.add_argument("--audience", required=True)
        if name == "verifier-request":
            command.add_argument("--service-day", required=True)
        if name == "wallet-decide":
            command.add_argument("--review-hash", required=True)
            command.add_argument("--decision", required=True, choices=("approve", "deny"))
    return result


def run(args):
    name, private = args.command, args.store
    registry = getattr(args, "registry", None)
    # Catch ordinary path mistakes before consuming an offer or consent decision.
    if hasattr(args, "out") and (args.out.exists() or not args.out.parent.is_dir()):
        raise Rejected("output_must_be_new_file_in_existing_directory")
    value = issuer.read_json(args.input) if hasattr(args, "input") else None
    if name == "issuer-init":
        return {"key_id": issuer.initialize(private, registry)}
    if name == "issuer-rotate":
        return {"key_id": issuer.rotate(private, registry)}
    if name == "issuer-key":
        return issuer.change_key(private, registry, args.key_id, args.action)
    if name == "issuer-offer":
        return issuer.offer(private, registry)
    if name == "issuer-issue":
        return issuer.issue(private, registry, value, can_drive=args.can_drive, valid_until=args.valid_until)
    if name == "issuer-revoke":
        return issuer.revoke_credential(private, registry, args.key_id, args.index)
    if name == "issuer-backup":
        return issuer.backup(private, args.backup)
    if name == "issuer-restore":
        return issuer.restore(private, registry, args.backup)
    if name == "verifier-init":
        return wallet.verifier_init(private, registry, args.audience)
    if name == "verifier-reset":
        return wallet.verifier_reset(private, registry)
    if name == "verifier-request":
        return wallet.request(private, registry, args.key_id, args.service_day)
    if name == "verifier-verify":
        return wallet.verify(private, registry, value)
    if name == "wallet-init":
        return wallet.wallet_init(private, registry, value)
    if name == "wallet-pair":
        return wallet.wallet_pair(private, registry, value)
    if name == "wallet-enroll":
        return wallet.enroll(private, registry, value)
    if name == "wallet-import":
        return wallet.import_credential(private, registry, value)
    if name == "wallet-review":
        return wallet.review(private, registry, value)
    if name == "wallet-decide":
        return wallet.present(private, registry, value, args.review_hash, approve=args.decision == "approve")
    raise Rejected("unknown_command")


def main():
    args = parser().parse_args()
    try:
        result = run(args)
        if hasattr(args, "out"):
            issuer.write_json(args.out, result)
            result = {"written": str(args.out)}
        print(json.dumps(result or {"ok": True}, sort_keys=True))
        return 0
    except Rejected as exc:
        print(json.dumps({"accepted": False, "reason": str(exc)}))
        return 1
    except (ValueError, TypeError, KeyError, IndexError, OSError, sqlite3.Error, backend().AnoncredsError):
        # Backend errors may include credential values. Never echo those to logs.
        print(json.dumps({"accepted": False, "reason": "invalid_input_or_operation_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

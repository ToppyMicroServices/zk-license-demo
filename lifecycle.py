"""Synthetic issuer state and an operator-provisioned public trust registry.

SQLite rollback journals make issuer/public updates atomic on one local disk.
The registry is trusted configuration, not a remotely authenticated directory.
"""
from __future__ import annotations

from contextlib import contextmanager, closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3

from request_store import Rejected, day_number
from zk_license import ATTRIBUTES, backend

CAPACITY = 100


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def write_json(path, value):
    # Refuse overwrites; issuance files and backups can contain private material.
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(canonical(value) + "\n")


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Rejected("duplicate_json_key")
            result[key] = value
        return result

    def invalid(_):
        raise Rejected("invalid_json_number")

    with open(path, "rb") as source:
        data = source.read(2_000_001)
    if len(data) > 2_000_000:
        raise Rejected("file_too_large")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def connect(path, *, readonly=False):
    # mode prevents a typo from silently creating a fresh database.
    uri = Path(path).resolve().as_uri() + ("?mode=ro" if readonly else "?mode=rw")
    return sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)


def create_store(path, role, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    with closing(connect(path)) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE state (role TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        con.execute("INSERT INTO state VALUES (?,?)", (role, canonical(data)))


def load(con, role, db="main"):
    row = con.execute(f"SELECT payload FROM {db}.state WHERE role=?", (role,)).fetchone()
    if row is None:
        raise Rejected("wrong_store_role")
    return json.loads(row[0])


def save(con, role, data, db="main"):
    con.execute(f"UPDATE {db}.state SET payload=? WHERE role=?", (canonical(data), role))


@contextmanager
def store(path, role, *, write=False):
    with closing(connect(path, readonly=not write)) as con:
        con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            data = load(con, role)
            yield data
            if write:
                save(con, role, data)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise


@contextmanager
def issuer_transaction(private, registry):
    with closing(connect(private)) as con:
        con.execute("ATTACH DATABASE ? AS registry", (Path(registry).resolve().as_uri() + "?mode=rw",))
        # WAL would lose atomicity across attached databases after a crash.
        for db in ("main", "registry"):
            if con.execute(f"PRAGMA {db}.journal_mode").fetchone()[0] != "delete":
                raise Rejected("rollback_journal_required")
            con.execute(f"PRAGMA {db}.synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        try:
            issuer, public = load(con, "issuer"), load(con, "registry", "registry")
            if issuer["instance"] != public["instance"]:
                raise Rejected("wrong_registry")
            yield issuer, public
            save(con, "issuer", issuer)
            save(con, "registry", public, "registry")
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise


def initialize(private, registry):
    if Path(private).resolve() == Path(registry).resolve():
        raise Rejected("separate_stores_required")
    if Path(private).exists() or Path(registry).exists():
        raise Rejected("store_already_exists")
    instance = secrets.token_hex(16)
    create_store(private, "issuer", {"instance": instance, "keys": {}, "offers": {}})
    create_store(registry, "registry", {"instance": instance, "revision": 0, "keys": {}})
    return rotate(private, registry)


def rotate(private, registry):
    ac = backend()
    with issuer_transaction(private, registry) as (issuer, public):
        key_id = secrets.token_hex(16)
        issuer_id = "https://synthetic.issuer.example/" + public["instance"]
        schema_id = issuer_id + "/schema/v1"
        cred_id = issuer_id + "/credentials/" + key_id
        rev_id = cred_id + "/revocation/1"
        schema = ac.Schema.create("synthetic-license", "1.0", issuer_id, ATTRIBUTES)
        cred_def, secret, correctness = ac.CredentialDefinition.create(
            schema_id, schema, issuer_id, key_id, "CL", support_revocation=True)
        tails = Path(registry).resolve().parent / "tails"
        tails.mkdir(exist_ok=True)
        rev_def, rev_secret = ac.RevocationRegistryDefinition.create(
            cred_id, cred_def, issuer_id, key_id, "CL_ACCUM", CAPACITY,
            tails_dir_path=str(tails))
        public["revision"] += 1
        status = ac.RevocationStatusList.create(
            cred_def, rev_id, rev_def, rev_secret, issuer_id,
            # Match the upstream Python demo and fresh-witness construction.
            # An unallocated slot still needs a valid issuer signature to prove.
            issuance_by_default=True, timestamp=public["revision"])
        for key in public["keys"].values():
            if key["state"] == "active":
                key["state"] = "verify_only"
        public["keys"][key_id] = {
            "state": "active", "schema_id": schema_id, "schema": schema.to_dict(),
            "cred_def_id": cred_id, "cred_def": cred_def.to_dict(),
            "rev_reg_id": rev_id, "rev_reg_def": rev_def.to_dict(),
            "status": status.to_dict(), "next_index": 1,
        }
        issuer["keys"][key_id] = {
            "cred_def_private": secret.to_dict(), "correctness": correctness.to_dict(),
            "rev_reg_private": rev_secret.to_dict(),
            "public_digest": digest({"cred_def": cred_def.to_dict(), "rev_reg_def": rev_def.to_dict()}),
        }
        return key_id


def trusted_key(public, key_id):
    key = public["keys"].get(key_id)
    if key is None or key["state"] not in ("active", "verify_only"):
        raise Rejected("untrusted_issuer_key")
    return key


def change_key(private, registry, key_id, action):
    if action not in ("rollback", "retire", "revoke"):
        raise Rejected("unknown_key_action")
    with issuer_transaction(private, registry) as (issuer, public):
        key = trusted_key(public, key_id)  # Terminal states cannot be reactivated.
        if action == "rollback":
            if key_id not in issuer["keys"]:
                raise Rejected("private_key_unavailable")
            for old in public["keys"].values():
                if old["state"] == "active":
                    old["state"] = "verify_only"
            key["state"] = "active"
        else:
            key["state"] = "retired" if action == "retire" else "revoked"
        public["revision"] += 1
        issuer["offers"].clear()


def offer(private, registry):
    ac = backend()
    with issuer_transaction(private, registry) as (issuer, public):
        active = [i for i, k in public["keys"].items() if k["state"] == "active"]
        if len(active) != 1 or active[0] not in issuer["keys"]:
            raise Rejected("active_private_key_unavailable")
        key_id = active[0]
        key = public["keys"][key_id]
        value = ac.CredentialOffer.create(key["schema_id"], key["cred_def_id"],
                                         issuer["keys"][key_id]["correctness"]).to_dict()
        offer_id = secrets.token_hex(16)
        issuer["offers"][offer_id] = {"key_id": key_id, "offer": value}
        return {"instance": public["instance"], "offer_id": offer_id,
                "key_id": key_id, "offer": value}


def update_status(public, key, secret, *, issued=None, revoked=None):
    ac = backend()
    public["revision"] += 1
    key["status"] = ac.RevocationStatusList.load(key["status"]).update(
        ac.CredentialDefinition.load(key["cred_def"]), key["rev_reg_def"],
        ac.RevocationRegistryDefinitionPrivate.load(secret["rev_reg_private"]),
        issued, revoked, public["revision"]).to_dict()


def issue(private, registry, enrollment, *, can_drive=1, valid_until="2031-12-31"):
    if type(can_drive) is not int or can_drive not in (0, 1):
        raise Rejected("invalid_entitlement")
    expiry = day_number(valid_until)
    ac = backend()
    with issuer_transaction(private, registry) as (issuer, public):
        if set(enrollment) != {"instance", "offer_id", "request"} or enrollment["instance"] != public["instance"]:
            raise Rejected("invalid_enrollment")
        pending = issuer["offers"].get(enrollment["offer_id"])
        if pending is None:
            raise Rejected("unknown_offer")
        key_id = pending["key_id"]
        key, secret = trusted_key(public, key_id), issuer["keys"][key_id]
        if key["state"] != "active" or key["next_index"] >= CAPACITY:
            raise Rejected("key_inactive_or_registry_full")
        index = key["next_index"]
        raw = dict(zip(ATTRIBUTES, ["SAMPLE PERSON", "SYNTHETIC ADDRESS", "19900405",
                                   "DEMO-NOT-A-LICENSE", str(can_drive), str(expiry)]))
        config = ac.CredentialRevocationConfig(
            ac.RevocationRegistryDefinition.load(key["rev_reg_def"]),
            ac.RevocationRegistryDefinitionPrivate.load(secret["rev_reg_private"]),
            ac.RevocationStatusList.load(key["status"]), index)
        credential = ac.Credential.create(key["cred_def"], secret["cred_def_private"],
                                         pending["offer"], enrollment["request"], raw,
                                         revocation_config=config)
        update_status(public, key, secret, issued=[index])
        key["next_index"] += 1
        del issuer["offers"][enrollment["offer_id"]]
        return {"instance": public["instance"], "offer_id": enrollment["offer_id"],
                "key_id": key_id, "credential": credential.to_dict()}


def revoke_credential(private, registry, key_id, index):
    with issuer_transaction(private, registry) as (issuer, public):
        key = trusted_key(public, key_id)
        if type(index) is not int or not 1 <= index < key["next_index"]:
            raise Rejected("unknown_credential_index")
        update_status(public, key, issuer["keys"][key_id], revoked=[index])


def backup(private, destination):
    with store(private, "issuer") as issuer:
        write_json(destination, issuer)


def restore(private, registry, source):
    snapshot = read_json(source)
    if not Path(private).exists():
        with store(registry, "registry") as public:
            if snapshot["instance"] != public["instance"]:
                raise Rejected("wrong_backup_registry")
            create_store(private, "issuer", {"instance": public["instance"], "keys": {}, "offers": {}})
    with issuer_transaction(private, registry) as (issuer, public):
        if snapshot["instance"] != public["instance"]:
            raise Rejected("wrong_backup_registry")
        recovered = {}
        for key_id, secret in snapshot["keys"].items():
            key = public["keys"].get(key_id)
            if key is None or key["state"] not in ("active", "verify_only"):
                continue
            expected = digest({"cred_def": key["cred_def"], "rev_reg_def": key["rev_reg_def"]})
            if secret["public_digest"] != expected:
                raise Rejected("backup_key_mismatch")
            recovered[key_id] = secret
        issuer["keys"] = recovered
        issuer["offers"] = {}
        # Public tombstones, status lists and allocation counters are authoritative.
        # Never restore these from the private backup.


def checkpoint(local, public):
    if local["instance"] != public["instance"]:
        raise Rejected("wrong_registry")
    revision, fingerprint = public["revision"], digest(public)
    if revision < local["revision"] or (revision == local["revision"] and fingerprint != local["digest"]):
        raise Rejected("registry_rollback_or_equivocation")
    local.update(revision=revision, digest=fingerprint)


def initial_checkpoint(public):
    return {"instance": public["instance"], "revision": public["revision"], "digest": digest(public)}

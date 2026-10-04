"""Policy/state tests only. True/False callbacks are NOT cryptographic proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from demo import read_json
from request_store import Challenge, Rejected, RequestStore, day_number
from zk_license import PublicTrust, allowed_presentation_shape


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "requests.sqlite3"
        self.store = RequestStore(self.path)
        self.challenge = Challenge.new(audience="https://verifier.example", session="authenticated-demo-session",
                                       service_day="2030-06-01", now=1000)
        self.store.add(self.challenge)

    def consume(self, **kwargs):
        values = dict(audience=self.challenge.audience, session=self.challenge.session,
                      verify=lambda request: True, now=1001)
        values.update(kwargs)
        self.store.consume(self.challenge.request_id, **values)

    def test_date_encoding(self):
        self.assertEqual(day_number("2028-02-29"), 20280229)
        for value in ("2029-02-29", "2028-2-29", "20280229", "2030-06-01T00:00:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                day_number(value)

    def test_policy_has_two_pinned_predicates(self):
        request = self.challenge.proof_request("https://issuer.example/pinned")
        self.assertEqual(request["requested_attributes"], {})
        self.assertEqual(set(request["requested_predicates"]), {"ordinary", "expiry"})
        self.assertEqual(request["requested_predicates"]["expiry"]["p_value"], 20300601)
        for value in request["requested_predicates"].values():
            self.assertEqual(value["restrictions"], [{"cred_def_id": "https://issuer.example/pinned"}])

    def test_challenges_are_distinct(self):
        other = Challenge.new(audience=self.challenge.audience, session=self.challenge.session,
                              service_day=self.challenge.service_day, now=1000)
        self.assertNotEqual(other.nonce, self.challenge.nonce)
        self.assertNotEqual(other.request_id, self.challenge.request_id)

    def test_invalid_ttl(self):
        for ttl in (0, -1, 601):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                Challenge.new(audience="a", session="s", service_day="2030-06-01", ttl=ttl)

    def test_accept_then_reject_replay(self):
        self.consume()
        with self.assertRaisesRegex(Rejected, "already_used"):
            self.consume()

    def test_replay_state_survives_restart(self):
        self.consume()
        self.store = RequestStore(self.path)
        with self.assertRaisesRegex(Rejected, "already_used"):
            self.consume()

    def test_wrong_audience_does_not_consume(self):
        with self.assertRaisesRegex(Rejected, "wrong_audience"):
            self.consume(audience="https://other.example")
        self.consume()

    def test_wrong_session_does_not_consume(self):
        with self.assertRaisesRegex(Rejected, "wrong_session"):
            self.consume(session="other-session")
        self.consume()

    def test_wrong_context_prevents_crypto_callback(self):
        called = []
        with self.assertRaises(Rejected):
            self.consume(session="other-session", verify=lambda req: called.append(req))
        self.assertEqual(called, [])

    def test_unknown_request(self):
        with self.assertRaisesRegex(Rejected, "unknown_request"):
            self.store.consume("nonexistent", audience="a", session="s", verify=lambda _: True, now=1001)

    def test_exact_deadline_is_expired(self):
        with self.assertRaisesRegex(Rejected, "expired"):
            self.consume(now=self.challenge.expires_at)

    def test_backwards_clock_is_rejected(self):
        with self.assertRaisesRegex(Rejected, "clock_invalid"):
            self.consume(now=999)

    def test_bad_proof_does_not_consume(self):
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            self.consume(verify=lambda _: False)
        self.consume()

    def test_truthy_non_boolean_callback_rejected(self):
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            self.consume(verify=lambda _: "True")

    def test_callback_exception_rolls_back(self):
        def broken(_):
            raise RuntimeError("intentional callback failure")
        with self.assertRaisesRegex(RuntimeError, "intentional"):
            self.consume(verify=broken)
        self.consume()

    def test_concurrent_replay_only_one_acceptance(self):
        def worker(_):
            try:
                self.consume()
                return "accepted"
            except Rejected as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(worker, range(2)))
        self.assertCountEqual(result, ["accepted", "already_used"])


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "input.json"

    def test_duplicate_json_rejected(self):
        self.path.write_text('{"nonce":"1","nonce":"2"}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            read_json(self.path)

    def test_nonfinite_json_rejected(self):
        self.path.write_text('{"nonce":NaN}')
        with self.assertRaisesRegex(ValueError, "Non-finite"):
            read_json(self.path)

    def test_json_size_limit(self):
        self.path.write_text(' ' * 1_048_577)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            read_json(self.path)

    def test_json_must_be_object(self):
        self.path.write_text('[]')
        with self.assertRaisesRegex(ValueError, "object"):
            read_json(self.path)


class ShapeTests(unittest.TestCase):
    """These are intentionally non-cryptographic structure fixtures, not proofs."""
    def setUp(self):
        self.trust = PublicTrust("schema", "definition", {}, {})
        self.value = {
            "proof": {},
            "requested_proof": {"revealed_attrs": {}, "unrevealed_attrs": {},
                                "self_attested_attrs": {},
                                "predicates": {"ordinary": {"sub_proof_index": 0},
                                               "expiry": {"sub_proof_index": 0}}},
            "identifiers": [{"schema_id": "schema", "cred_def_id": "definition",
                             "rev_reg_id": None, "timestamp": None}],
        }

    def test_minimal_shape_only(self):
        self.assertTrue(allowed_presentation_shape(self.value, self.trust))

    def test_unknown_issuer(self):
        self.value["identifiers"][0]["cred_def_id"] = "untrusted"
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_additional_identity_value_rejected(self):
        self.value["requested_proof"]["revealed_attrs"] = {"full_name": {"raw": "SAMPLE"}}
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_self_attestation_rejected(self):
        self.value["requested_proof"]["self_attested_attrs"] = {"ordinary": "yes"}
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_mixed_credentials_rejected(self):
        self.value["requested_proof"]["predicates"]["expiry"]["sub_proof_index"] = 1
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_missing_predicate_rejected(self):
        del self.value["requested_proof"]["predicates"]["expiry"]
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_extra_envelope_field_rejected(self):
        self.value["holder_name"] = "SAMPLE"
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_revocation_not_silently_supported(self):
        self.value["identifiers"][0]["timestamp"] = 10
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_boolean_index_rejected(self):
        self.value["requested_proof"]["predicates"]["expiry"]["sub_proof_index"] = False
        self.assertFalse(allowed_presentation_shape(self.value, self.trust))

    def test_malformed_input_rejected(self):
        for value in (None, [], 1, {}, {"proof": "not a proof"}):
            with self.subTest(value=value):
                self.assertFalse(allowed_presentation_shape(value, self.trust))

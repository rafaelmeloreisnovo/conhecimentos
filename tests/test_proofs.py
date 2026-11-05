import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_proofs import ENVELOPE, PAYLOAD, InvalidProof, parse, validate


class ProofGateTests(unittest.TestCase):
    def setUp(self):
        self.doc = {
            "schema": PAYLOAD,
            "event_id": "25bb01cd-9ef1-41a2-8c9e-024b24b3d8ec",
            "captured_at_utc": "2026-11-05T20:00:00Z",
            "app_version": "0.1.0",
            "android_sdk": 29,
            "credential_present": True,
            "auth_flag": True,
            "profile_visible": False,
            "repository_count": 0,
            "repository_listing_complete": False,
            "live_probe": "PASS_SCOPED",
            "capture_scope": "ANDROID_APP_SELF_REPORT",
            "device_attestation": "TOKEN_VAZIO",
            "source_commit": "TOKEN_VAZIO",
            "claim_allowed": False,
        }

    def envelope(self):
        raw = json.dumps(self.doc, sort_keys=True, separators=(",", ":"))
        return {
            "schema": ENVELOPE,
            "payload_json": raw,
            "payload_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }

    def test_valid_self_report(self):
        self.assertEqual(validate(self.envelope())["repository_count"], 0)

    def test_modified_payload_digest_rejected(self):
        e = self.envelope()
        e["payload_json"] = e["payload_json"].replace('"repository_count":0', '"repository_count":1')
        with self.assertRaises(InvalidProof):
            validate(e)

    def test_self_report_cannot_promote(self):
        self.doc["claim_allowed"] = True
        with self.assertRaises(InvalidProof):
            validate(self.envelope())

    def test_no_forged_attestation(self):
        self.doc["device_attestation"] = "PASS"
        with self.assertRaises(InvalidProof):
            validate(self.envelope())

    def test_secret_and_email_blocked(self):
        self.doc["app_version"] = "github_pat_secret"
        with self.assertRaises(InvalidProof):
            validate(self.envelope())
        self.doc["app_version"] = "me@example.org"
        with self.assertRaises(InvalidProof):
            validate(self.envelope())

    def test_bad_boolean_and_missing_auth_rejected(self):
        self.doc["auth_flag"] = 1
        with self.assertRaises(InvalidProof):
            validate(self.envelope())
        self.doc["auth_flag"] = False
        self.doc["profile_visible"] = True
        with self.assertRaises(InvalidProof):
            validate(self.envelope())

    def test_json_duplicate_key_rejected(self):
        with self.assertRaises(InvalidProof):
            parse('{"schema":"first","schema":"second"}')


if __name__ == "__main__":
    unittest.main()

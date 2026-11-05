#!/usr/bin/env python3
"""Verify privacy-bounded Android self-report envelopes; never assert device attestation."""
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

ENVELOPE = "rafaelia.public-proof-envelope/v1"
PAYLOAD = "rafaelia.rafgittools.device-evidence/v1"
REQUIRED = {
    "schema", "event_id", "captured_at_utc", "app_version", "android_sdk",
    "credential_present", "auth_flag", "profile_visible", "repository_count",
    "repository_listing_complete", "live_probe", "capture_scope",
    "device_attestation", "source_commit", "claim_allowed",
}
SENSITIVE = re.compile(
    r"(?i)(github_pat_|gh[opusr]_|bearer\s+|authorization\s*:|"
    r"-----begin [a-z ]*private key-----|"
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|"
    r"/(?:storage|data|sdcard|home)/|https?://)"
)
SHA = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[a-zA-Z0-9_.+-]{1,64}")


class InvalidProof(ValueError):
    pass


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidProof("duplicate_json_key")
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_pairs)


def validate(envelope):
    if type(envelope) is not dict or set(envelope) != {
        "schema", "payload_json", "payload_sha256"
    } or envelope["schema"] != ENVELOPE:
        raise InvalidProof("envelope_invalid")
    raw = envelope["payload_json"]
    if type(raw) is not str or not (10 <= len(raw.encode("utf8")) <= 4096):
        raise InvalidProof("payload_length_invalid")
    digest = envelope["payload_sha256"]
    if type(digest) is not str or not SHA.fullmatch(digest):
        raise InvalidProof("digest_format_invalid")
    if hashlib.sha256(raw.encode("utf8")).hexdigest() != digest:
        raise InvalidProof("payload_digest_mismatch")
    if SENSITIVE.search(raw):
        raise InvalidProof("public_payload_may_contain_sensitive_data")
    doc = parse(raw)
    if type(doc) is not dict or set(doc) != REQUIRED or doc["schema"] != PAYLOAD:
        raise InvalidProof("payload_shape_invalid")
    try:
        if uuid.UUID(doc["event_id"]).version != 4:
            raise ValueError("event_id_not_random_uuid_v4")
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidProof("event_id_invalid") from exc
    stamp = doc["captured_at_utc"]
    if type(stamp) is not str or not stamp.endswith("Z"):
        raise InvalidProof("timestamp_invalid")
    try:
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidProof("timestamp_invalid") from exc
    if type(doc["app_version"]) is not str or not VERSION.fullmatch(doc["app_version"]):
        raise InvalidProof("app_version_invalid")
    sdk, count = doc["android_sdk"], doc["repository_count"]
    if type(sdk) is not int or not 16 <= sdk <= 99:
        raise InvalidProof("android_sdk_invalid")
    if type(count) is not int or not 0 <= count <= 100000:
        raise InvalidProof("repo_count_invalid")
    for name in (
        "credential_present", "auth_flag", "profile_visible",
        "repository_listing_complete", "claim_allowed"
    ):
        if type(doc[name]) is not bool:
            raise InvalidProof("boolean_field_invalid:" + name)
    if doc["claim_allowed"]:
        raise InvalidProof("self_report_cannot_allow_claim")
    if doc["live_probe"] not in ("NOT_RUN", "PASS_SCOPED", "FAILED"):
        raise InvalidProof("probe_state_invalid")
    if doc["capture_scope"] != "ANDROID_APP_SELF_REPORT":
        raise InvalidProof("capture_scope_not_proven")
    if doc["device_attestation"] != "TOKEN_VAZIO":
        raise InvalidProof("device_attestation_not_observed")
    commit = doc["source_commit"]
    if commit != "TOKEN_VAZIO" and (type(commit) is not str or not COMMIT.fullmatch(commit)):
        raise InvalidProof("source_commit_invalid")
    if not doc["auth_flag"] and (
        doc["profile_visible"] or doc["repository_count"] > 0
        or doc["repository_listing_complete"]
    ):
        raise InvalidProof("auth_state_inconsistent")
    return doc


def verify_file(path):
    path = Path(path)
    if path.stat().st_size > 8192:
        raise InvalidProof("envelope_oversize")
    envelope = parse(path.read_text(encoding="utf8"))
    return validate(envelope)


def main(paths):
    if not paths:
        paths = sorted(Path("proofs").glob("*.json"))
    if not paths:
        print("PASS_SCOPED schema_gate; public_proofs=0; DEVICE_E2E=NOT_RUN")
        return
    for path in paths:
        verify_file(path)
    print(f"PASS_SCOPED envelopes={len(paths)}; DEVICE_ATTESTATION=TOKEN_VAZIO")


if __name__ == "__main__":
    try:
        main([Path(p) for p in sys.argv[1:]])
    except (ValueError, OSError, TypeError) as error:
        sys.exit("FAIL " + str(error))

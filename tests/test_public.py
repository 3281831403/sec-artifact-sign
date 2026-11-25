import json
from datetime import datetime, timezone

from artsign.verify import (
    bundle_batch,
    parse_bundle,
    verify_bundle,
    verify_one,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64

KEYRING = {
    "alice": "sig-alice-1",
    "bob": "sig-bob-1",
}


def make_signature(signer, digest, value, start="2026-01-01T00:00:00Z", end="2027-01-01T00:00:00Z"):
    return {
        "signer": signer,
        "digest": digest,
        "value": value,
        "start": start,
        "end": end,
    }


def make_bundle(digest, threshold, signatures):
    payload = {
        "artifact": "demo-app",
        "digest": digest,
        "threshold": threshold,
        "signatures": signatures,
    }
    return parse_bundle(json.dumps(payload))


def make_policy(threshold):
    return {
        "threshold": threshold,
        "allowlist": ["alice", "bob"],
        "keyring": KEYRING,
    }


def test_single_valid_signature_passes():
    bundle = make_bundle(DIGEST_A, 3, [make_signature("alice", DIGEST_A, KEYRING["alice"])])
    assert verify_bundle(bundle, KEYRING, make_policy(1), NOW)["ok"] is True


def test_two_signatures_meet_threshold():
    bundle = make_bundle(
        DIGEST_A,
        5,
        [
            make_signature("alice", DIGEST_A, KEYRING["alice"]),
            make_signature("bob", DIGEST_A, KEYRING["bob"]),
        ],
    )
    assert verify_bundle(bundle, KEYRING, make_policy(2), NOW)["ok"] is True


def test_digest_mismatch_is_rejected():
    signature = make_signature("alice", DIGEST_B, KEYRING["alice"])
    assert verify_one(signature, DIGEST_A, KEYRING) is False


def test_duplicate_signer_counts_once():
    bundle = make_bundle(
        DIGEST_A,
        2,
        [
            make_signature("alice", DIGEST_A, KEYRING["alice"]),
            make_signature("alice", DIGEST_A, KEYRING["alice"]),
        ],
    )
    assert verify_bundle(bundle, KEYRING, make_policy(2), NOW)["ok"] is False


def test_batch_keeps_artifacts_independent():
    bundles = {
        "first": make_bundle(
            DIGEST_A,
            2,
            [
                make_signature("alice", DIGEST_A, KEYRING["alice"]),
                make_signature("bob", DIGEST_A, KEYRING["bob"]),
            ],
        ),
        "second": make_bundle(
            DIGEST_C,
            2,
            [make_signature("alice", DIGEST_C, KEYRING["alice"])],
        ),
    }
    results = bundle_batch(bundles, make_policy(2), NOW)
    assert results["first"]["ok"] is True
    assert results["second"]["ok"] is False
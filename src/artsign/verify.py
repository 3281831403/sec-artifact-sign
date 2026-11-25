"""Multi-signature artifact bundle verification.

A bundle names an artifact digest, a declared threshold and a list of
signatures.  Each signature carries the signer identity, the digest it was
issued for, a validity window and an opaque value that is checked against
the keyring.  Verification combines the bundle with a policy supplied by
the caller and returns a small result mapping.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _parse_time(value):
    """Return an aware datetime for an ISO-8601 value, or None."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_bundle(text):
    """Parse a JSON signature bundle into a plain dictionary."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("bundle must be a JSON object")
    raw_signatures = data.get("signatures") or []
    if not isinstance(raw_signatures, list):
        raise ValueError("signatures must be a list")
    signatures = []
    for item in raw_signatures:
        if not isinstance(item, dict):
            raise ValueError("each signature must be an object")
        signatures.append(dict(item))
    bundle = dict(data)
    bundle["digest"] = data.get("digest") or ""
    bundle["threshold"] = int(data.get("threshold") or 0)
    bundle["signatures"] = signatures
    return bundle


def verify_one(signature, digest, keyring):
    """Check one signature value against the key registered for its signer."""
    signer = signature.get("signer")
    if not isinstance(signer, str) or signer not in keyring:
        return False
    expected = keyring[signer]
    if not isinstance(expected, str):
        return False
    return signature.get("value") == expected


def check_validity(signature, now, policy):
    """Check that the signature validity window contains now (inclusive)."""
    start = _parse_time(signature.get("start"))
    end = _parse_time(signature.get("end"))
    moment = _parse_time(now)
    if start is None or end is None or moment is None:
        return False
    if end < start:
        return False
    return start <= moment


def check_authorized(signer, allowlist):
    """Check that signer appears in the authorization list."""
    if not isinstance(signer, str):
        return False
    return signer in (allowlist or [])


def count_unique(signatures):
    """Count distinct signers among signatures."""
    signers = set()
    for signature in signatures:
        signer = signature.get("signer")
        if isinstance(signer, str):
            signers.add(signer)
    return len(signers)


def verify_bundle(bundle, keyring, policy, now):
    """Verify a parsed bundle against a keyring and a threshold policy."""
    signatures = bundle.get("signatures") or []
    threshold = int(bundle.get("threshold") or 0)
    digest = bundle.get("digest") or ""
    if not signatures:
        return {
            "ok": True,
            "count": 0,
            "threshold": threshold,
            "signers": [],
        }
    accepted = []
    for signature in signatures:
        if len(signature.get("digest") or "") != len(digest):
            continue
        if verify_one(signature, digest, keyring):
            accepted.append(signature)
    return {
        "ok": len(accepted) >= threshold,
        "count": len(accepted),
        "threshold": threshold,
        "signers": [signature.get("signer") for signature in accepted],
    }


def validate_bundle(bundle):
    """Return a list of human readable problems found in a bundle."""
    if not isinstance(bundle, dict):
        return ["bundle must be a mapping"]
    issues = []
    if not bundle.get("digest"):
        issues.append("missing artifact digest")
    signatures = bundle.get("signatures")
    if not signatures:
        issues.append("empty bundle")
        return issues
    seen = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            issues.append("signature must be a mapping")
            continue
        signer = signature.get("signer")
        if not signer:
            issues.append("signature is missing a signer")
            continue
        if signer in seen:
            issues.append("duplicate signer: " + str(signer))
        else:
            seen.add(signer)
        if not signature.get("digest"):
            issues.append("signature is missing a digest: " + str(signer))
        if not signature.get("value"):
            issues.append("signature is missing a value: " + str(signer))
    return issues


def bundle_batch(bundles, policy, now):
    """Verify a mapping of artifact name to bundle and return each result."""
    threshold = int(policy.get("threshold") or 0)
    results = {}
    running = 0
    for name, bundle in bundles.items():
        running += len(bundle.get("signatures") or [])
        results[name] = {
            "ok": running >= threshold,
            "count": running,
            "threshold": threshold,
        }
    return results
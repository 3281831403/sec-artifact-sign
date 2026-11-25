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
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _policy_threshold(policy):
    """Return the threshold declared by the verification policy."""
    if not isinstance(policy, dict):
        return 0
    try:
        return int(policy.get("threshold") or 0)
    except (TypeError, ValueError):
        return 0


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
    try:
        bundle["threshold"] = int(data.get("threshold") or 0)
    except (TypeError, ValueError):
        bundle["threshold"] = 0
    bundle["signatures"] = signatures
    return bundle


def verify_one(signature, digest, keyring):
    """Check one signature against the digest, its signer's key and the keyring."""
    if not isinstance(signature, dict) or not isinstance(digest, str) or not digest:
        return False
    if signature.get("digest") != digest:
        return False
    signer = signature.get("signer")
    if not isinstance(signer, str) or signer not in (keyring or {}):
        return False
    expected = keyring[signer]
    if not isinstance(expected, str):
        return False
    return signature.get("value") == expected


def check_validity(signature, now, policy=None):
    """Check that the signature validity window contains now (inclusive)."""
    if not isinstance(signature, dict):
        return False
    start = _parse_time(signature.get("start"))
    end = _parse_time(signature.get("end"))
    moment = _parse_time(now)
    if start is None or end is None or moment is None:
        return False
    if end < start:
        return False
    return start <= moment <= end


def check_authorized(signer, allowlist):
    """Check that signer appears in the authorization list."""
    if not isinstance(signer, str) or not signer:
        return False
    if not isinstance(allowlist, (list, tuple, set, frozenset)):
        return False
    return signer in allowlist


def count_unique(signatures):
    """Count distinct signers among signatures."""
    signers = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            continue
        signer = signature.get("signer")
        if isinstance(signer, str) and signer:
            signers.add(signer)
    return len(signers)


def _accepted_signers(bundle, keyring, policy, now):
    """Return the sorted set of signers with a fully valid signature."""
    digest = bundle.get("digest") or ""
    allowlist = policy.get("allowlist") if isinstance(policy, dict) else None
    accepted = set()
    for signature in bundle.get("signatures") or []:
        if not isinstance(signature, dict):
            continue
        if not verify_one(signature, digest, keyring):
            continue
        if not check_authorized(signature.get("signer"), allowlist):
            continue
        if not check_validity(signature, now, policy):
            continue
        accepted.add(signature.get("signer"))
    return sorted(accepted)


def verify_bundle(bundle, keyring, policy, now):
    """Verify a parsed bundle against a keyring and a threshold policy.

    The threshold is taken from the policy only; a threshold declared by the
    bundle itself is ignored.  Each signer contributes at most once and every
    counted signature must bind the artifact digest, be authorized and be
    inside its own validity window at ``now``.
    """
    if not isinstance(bundle, dict):
        bundle = {}
    if isinstance(policy, dict) and keyring is None:
        keyring = policy.get("keyring")
    threshold = _policy_threshold(policy)
    accepted = _accepted_signers(bundle, keyring or {}, policy or {}, now)
    ok = threshold >= 1 and len(accepted) >= threshold
    return {
        "ok": ok,
        "count": len(accepted),
        "threshold": threshold,
        "signers": accepted,
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
        elif signature.get("digest") != bundle.get("digest"):
            issues.append("signature digest does not match artifact: " + str(signer))
        if not signature.get("value"):
            issues.append("signature is missing a value: " + str(signer))
        start = _parse_time(signature.get("start"))
        end = _parse_time(signature.get("end"))
        if start is None or end is None:
            issues.append("signature has an invalid validity window: " + str(signer))
        elif end < start:
            issues.append("signature window ends before it starts: " + str(signer))
    return issues


def bundle_batch(bundles, policy, now):
    """Verify a mapping of artifact name to bundle and return each result.

    Each artifact is judged on its own signatures; counts never accumulate
    across artifacts in the batch.
    """
    keyring = policy.get("keyring") if isinstance(policy, dict) else None
    results = {}
    for name, bundle in (bundles or {}).items():
        results[name] = verify_bundle(bundle, keyring, policy, now)
    return results

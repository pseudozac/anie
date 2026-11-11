"""Demo: real Ed25519 verification on synthetic ANIE data, entirely offline.

The ephemeral private key exists ONLY in memory. It is not a production
signing identity and must not be used to authorize real data publication.
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anie.demo import demo_observations
from anie.publish import publish_synthetic
from anie.signed_release import (
    SignedReleaseTrust, sign_synthetic_release, verify_signed_synthetic_release,
)


def main() -> None:
    with TemporaryDirectory(prefix="anie-signed-demo-") as tmp:
        target = Path(tmp) / "synthetic"
        publish_synthetic(demo_observations(), target, "2026-11-11T10:00:00Z")
        key = Ed25519PrivateKey.generate()  # Only a temporary sample signing identity.
        raw_public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        commit = "a" * 40  # Fictional test commit; NOT a verified GitHub provenance claim.
        sign_synthetic_release(
            target,
            key,
            source_commit=commit,
            release_sequence=1,
            issued_at="2026-11-11T10:01:00Z",
            expires_at="2026-11-12T10:01:00Z",
        )
        trust = SignedReleaseTrust(
            public_key_raw=raw_public,
            expected_source_commit=commit,
            last_accepted_sequence=0,
        )
        result = verify_signed_synthetic_release(
            target, trust, now="2026-11-11T11:00:00Z"
        )
        assert result["verified"] and result["publisher_signature_verified"]
        assert result["publisher_real_world_identity_verified"] is False
        print(json.dumps({
            "offline": True,
            "synthetic_only": True,
            "ephemeral_key": True,
            "signature_verified": result["publisher_signature_verified"],
            "real_publisher_identity_verified": result["publisher_real_world_identity_verified"],
            "release_sequence": result["release_sequence"],
            "observations": result["observations"],
            "intelligence_records": result["intelligence_records"],
        }, sort_keys=True))


if __name__ == "__main__":
    main()

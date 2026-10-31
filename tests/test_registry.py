"""The signed, DoS-resistant revocation registry."""

from __future__ import annotations

import dataclasses

import pytest

from foldward.crypto import new_signer, verifier_from_public
from foldward.registry import Revocation, RevocationRegistry


@pytest.fixture
def registry(signer, audit):
    # The registry only ever holds the circle's *public* verifier.
    return RevocationRegistry(signer.verifier(), audit)


def test_circle_signed_revocation_is_accepted(registry, signer, audit):
    assert registry.revoke("a", "r", signer) is True

    assert registry.is_revoked("a")
    assert len(registry) == 1
    rev = registry.get("a")
    assert (rev.agent_id, rev.reason, rev.issuer_ref) == ("a", "r", signer.public_ref)
    assert registry.all() == [rev]
    assert [e.data for e in audit.events("revocation.accepted")] == [{"agent": "a", "reason": "r"}]


def test_unknown_agent_is_not_revoked(registry):
    assert not registry.is_revoked("nobody")
    assert registry.get("nobody") is None
    assert registry.all() == []
    assert len(registry) == 0


@pytest.mark.parametrize("scheme", ["auto", "ed25519"])
def test_forged_revocation_cannot_weaponize_the_registry(scheme, audit):
    registry = RevocationRegistry(new_signer(scheme).verifier(), audit)
    forged = Revocation("v", "dos", "x", 0.0, "ed25519:AAAA")

    assert registry.submit(forged) is False

    assert not registry.is_revoked("v")
    assert len(registry) == 0
    assert audit.events("revocation.accepted") == []
    assert [e.data for e in audit.events("revocation.rejected")] == [{"agent": "v", "reason": "bad_signature"}]


def test_revocation_signed_by_an_attacker_key_is_rejected(registry):
    attacker = new_signer()
    # The attacker mints a perfectly well-formed revocation in a registry of its own...
    mine = RevocationRegistry(attacker.verifier())
    assert mine.revoke("healthy-agent", "dos", attacker) is True

    # ...but the circle's registry refuses it: it was not signed by the circle.
    assert registry.submit(mine.get("healthy-agent")) is False
    assert not registry.is_revoked("healthy-agent")


@pytest.mark.parametrize(
    "change",
    [{"agent_id": "healthy-agent"}, {"reason": "something else"}, {"issued_at": 1.0}],
    ids=["retarget", "rewrite-reason", "backdate"],
)
def test_a_genuine_revocation_cannot_be_altered_and_resubmitted(registry, signer, change):
    registry.revoke("a", "r", signer)
    altered = dataclasses.replace(registry.get("a"), **change)

    assert registry.submit(altered) is False
    assert not registry.is_revoked("healthy-agent")
    assert registry.get("a").reason == "r"


def test_revoke_requires_the_circle_signing_authority(registry, signer, audit):
    with pytest.raises(ValueError, match="signing authority"):
        registry.revoke("a", "r", signer.verifier())

    assert not registry.is_revoked("a")
    assert audit.events("revocation.accepted") == []


def test_registry_works_without_an_audit_log(signer):
    registry = RevocationRegistry(signer.verifier())

    assert registry.revoke("a", "r", signer) is True
    assert registry.submit(Revocation("v", "dos", "x", 0.0, "ed25519:AAAA")) is False
    assert registry.is_revoked("a")
    assert not registry.is_revoked("v")


def test_revocation_propagates_to_a_sentinel_holding_only_public_material(registry, signer):
    registry.revoke("a", "r", signer)
    sentinel = RevocationRegistry(verifier_from_public(signer.public_ref, signer.public_bytes()))

    assert sentinel.submit(registry.get("a")) is True
    assert sentinel.is_revoked("a")


def test_revoking_the_same_agent_twice_keeps_one_entry(registry, signer):
    assert registry.revoke("a", "first", signer) is True
    assert registry.revoke("a", "second", signer) is True

    assert len(registry) == 1
    assert registry.get("a").reason == "second"

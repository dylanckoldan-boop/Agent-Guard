"""Pluggable signers, verify-only handles, and the hash-chained audit log."""

from __future__ import annotations

import base64
import json

import pytest

from agent_guard import crypto
from agent_guard.crypto import (
    AuditLog,
    HybridSigner,
    SignatureError,
    Signer,
    new_signer,
    verifier_from_public,
)

MSG = b"revoke agent-7"


def _hybrid_supported() -> bool:
    try:
        new_signer("hybrid")
    except SignatureError:
        return False
    return True


requires_hybrid = pytest.mark.skipif(
    not _hybrid_supported(), reason="ML-DSA-65 is not available in this cryptography build"
)

# Schemes whose verifier() is a genuine verify-only handle. (HMAC is symmetric by design, so its
# "verifier" is the same object and can still sign.)
ASYMMETRIC = ["auto", "ed25519", pytest.param("hybrid", marks=requires_hybrid)]


# --------------------------------------------------------------------------- signers
def test_self_test_passes():
    assert crypto.self_test() is True


def test_self_test_fails_if_tampering_would_go_undetected(monkeypatch):
    monkeypatch.setattr(AuditLog, "verify", lambda self: (True, len(self)))

    assert crypto.self_test() is False


@pytest.mark.parametrize("verdict", [True, False], ids=["accepts-everything", "rejects-everything"])
def test_self_test_fails_if_the_signer_is_broken(monkeypatch, verdict):
    for cls in (crypto.HybridSigner, crypto.Ed25519Signer, crypto.HMACSigner):
        monkeypatch.setattr(cls, "verify", lambda self, message, signature: verdict)

    assert crypto.self_test() is False


def test_default_signer_is_the_strongest_scheme_available():
    expected = "ML-DSA-65+Ed25519" if _hybrid_supported() else "Ed25519"
    assert new_signer().scheme == expected


def test_default_signer_signs_and_verifies():
    s = new_signer()
    sig = s.sign(MSG)

    assert isinstance(s, Signer)
    assert s.can_sign()
    assert s.verify(MSG, sig)
    assert not s.verify(b"another message", sig)


@pytest.mark.parametrize("scheme", [*ASYMMETRIC, "hmac"])
def test_every_scheme_round_trips_and_rejects_tampering(scheme):
    s = new_signer(scheme)
    sig = s.sign(MSG)

    assert s.verify(MSG, sig)
    assert not s.verify(b"tampered", sig)
    assert not s.verify(MSG, "")


@pytest.mark.parametrize("scheme", ASYMMETRIC)
def test_verifier_handle_cannot_sign_but_still_verifies(scheme):
    s = new_signer(scheme)
    v = s.verifier()
    sig = s.sign(MSG)

    assert v.can_sign() is False
    assert v.verify(MSG, sig)
    assert not v.verify(b"tampered", sig)
    assert v.public_ref == s.public_ref
    with pytest.raises(SignatureError):
        v.sign(MSG)


@pytest.mark.parametrize("scheme", ASYMMETRIC)
def test_verifier_from_public_accepts_good_and_rejects_forged(scheme):
    s = new_signer(scheme)
    sig = s.sign(MSG)
    pub = verifier_from_public(s.public_ref, s.public_bytes())

    assert pub.can_sign() is False
    assert pub.verify(MSG, sig)
    assert not pub.verify(b"tampered", sig)
    # a well-formed signature, but made with an attacker's key
    assert not pub.verify(MSG, new_signer(scheme).sign(MSG))
    # garbage that merely carries the right scheme prefix
    assert not pub.verify(MSG, sig.split(":", 1)[0] + ":AAAA")


def test_hmac_signature_from_another_key_is_rejected():
    assert not new_signer("hmac").verify(MSG, new_signer("hmac").sign(MSG))


@requires_hybrid
def test_signature_from_a_different_scheme_is_rejected():
    hybrid, ed = new_signer("hybrid"), new_signer("ed25519")

    assert not ed.verify(MSG, hybrid.sign(MSG))
    assert not hybrid.verify(MSG, ed.sign(MSG))


@requires_hybrid
def test_hybrid_signature_needs_both_component_signatures():
    mine, other = HybridSigner.generate(), HybridSigner.generate()

    def parts(signer):
        return json.loads(base64.b64decode(signer.sign(MSG)[len("hybrid:"):]))

    def pack(envelope):
        return "hybrid:" + base64.b64encode(json.dumps(envelope).encode()).decode()

    ours, theirs = parts(mine), parts(other)
    assert mine.verify(MSG, pack(ours))  # sanity: a repacked genuine signature is valid
    assert not mine.verify(MSG, pack({"mldsa65": ours["mldsa65"], "ed25519": theirs["ed25519"]}))
    assert not mine.verify(MSG, pack({"mldsa65": theirs["mldsa65"], "ed25519": ours["ed25519"]}))


def test_auto_falls_back_to_ed25519_when_mldsa_is_missing(monkeypatch):
    monkeypatch.setattr(crypto, "_HAVE_MLDSA", False)

    s = new_signer()
    assert s.scheme == "Ed25519"
    assert s.verify(MSG, s.sign(MSG))
    with pytest.raises(SignatureError):
        new_signer("hybrid")


def test_auto_falls_back_to_hmac_without_the_cryptography_package(monkeypatch):
    monkeypatch.setattr(crypto, "_HAVE_MLDSA", False)
    monkeypatch.setattr(crypto, "_HAVE_ED25519", False)

    s = new_signer()
    assert s.scheme == "HMAC-SHA256"
    assert s.verify(MSG, s.sign(MSG))
    with pytest.raises(SignatureError):
        new_signer("ed25519")


# ----------------------------------------------------------------------- audit log
@pytest.fixture
def chain():
    log = AuditLog()
    for i in range(3):
        log.append(f"evt.{i}", {"i": i})
    return log


def test_audit_log_appends_and_verifies(audit):
    first = audit.append("selftest.a", {"x": 1})
    second = audit.append("selftest.b", {"x": 2})

    assert audit.verify() == (True, 2)
    assert len(audit) == 2
    assert (first.seq, second.seq) == (0, 1)
    assert first.prev_hash == AuditLog.GENESIS
    assert second.prev_hash == first.this_hash
    assert audit.head == second.this_hash


def test_empty_audit_log_verifies_and_has_the_genesis_head():
    log = AuditLog()

    assert log.verify() == (True, 0)
    assert log.head == AuditLog.GENESIS
    assert len(log) == 0


def test_append_without_data_stores_an_empty_dict():
    assert AuditLog().append("evt").data == {}


def test_mutating_an_entry_breaks_verification(audit):
    audit.append("selftest.a", {"x": 1})
    audit.append("selftest.b", {"x": 2})
    assert audit.verify() == (True, 2)

    audit._entries[0].data["x"] = 999

    ok, broken_at = audit.verify()
    assert ok is False
    assert broken_at == 0


def _edit_data(log):
    log._entries[1].data["i"] = 999


def _edit_event_name(log):
    log._entries[1].event = "forged"


def _edit_timestamp(log):
    log._entries[0].ts += 1.0


def _forge_hash(log):
    log._entries[0].this_hash = "f" * 64


def _delete_first(log):
    del log._entries[0]


def _delete_middle(log):
    del log._entries[1]


def _swap_first_two(log):
    log._entries[0], log._entries[1] = log._entries[1], log._entries[0]


@pytest.mark.parametrize(
    ("tamper", "broken_at"),
    [
        pytest.param(_edit_data, 1, id="edit-data"),
        pytest.param(_edit_event_name, 1, id="edit-event"),
        pytest.param(_edit_timestamp, 0, id="edit-timestamp"),
        pytest.param(_forge_hash, 0, id="forge-hash"),
        pytest.param(_delete_first, 1, id="delete-first"),
        pytest.param(_delete_middle, 2, id="delete-middle"),
        pytest.param(_swap_first_two, 1, id="reorder"),
    ],
)
def test_any_edit_deletion_or_reorder_breaks_the_chain(chain, tamper, broken_at):
    assert chain.verify() == (True, 3)

    tamper(chain)

    assert chain.verify() == (False, broken_at)


def test_sign_head_returns_a_signature_the_circle_can_verify(signer):
    log = AuditLog(signer)
    log.append("a")
    log.append("b")

    sig = log.sign_head()

    assert isinstance(sig, str)
    assert signer.verifier().verify(log.head.encode(), sig)


def test_sign_head_is_none_without_a_signing_authority(signer):
    assert AuditLog().sign_head() is None
    assert AuditLog(signer.verifier()).sign_head() is None


def test_signed_head_exposes_a_truncated_tail(signer):
    log = AuditLog(signer)
    for i in range(3):
        log.append("evt", {"i": i})
    signed_head, sig = log.head, log.sign_head()

    del log._entries[-1]  # an attacker silently drops the newest record

    assert log.verify() == (True, 2)  # the chain alone cannot see a missing tail...
    assert log.head != signed_head
    assert not signer.verifier().verify(log.head.encode(), sig)  # ...the signed head can


def test_events_and_tail_helpers(audit):
    for name in ("a", "b", "a"):
        audit.append(name)

    assert [e.seq for e in audit.events("a")] == [0, 2]
    assert [e.event for e in audit.events()] == ["a", "b", "a"]
    assert [e.seq for e in audit.tail(2)] == [1, 2]

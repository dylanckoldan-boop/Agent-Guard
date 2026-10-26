"""Admission: signed, least-privilege agent credentials."""

from __future__ import annotations

import dataclasses

import pytest

from agent_guard.crypto import new_signer
from agent_guard.identity import Credential, Scope, TrustDomain, verify_credential

SCOPE = Scope(
    allowed_actions=frozenset({"read_logs", "summarize"}),
    allowed_hosts=frozenset({"logs.example.com"}),
    allowed_path_prefixes=frozenset({"/var/log/app/"}),
)


@pytest.fixture
def domain(signer):
    return TrustDomain(signer)


# ------------------------------------------------------------------- credentials
def test_issued_credential_verifies(domain, signer):
    cred = domain.issue("agent-1", SCOPE)

    assert domain.verify(cred)
    assert verify_credential(domain.circle_verifier, cred)
    assert cred.agent_id == "agent-1"
    assert cred.scope == SCOPE
    assert cred.issuer_ref == signer.public_ref


def test_a_verify_only_holder_can_check_credentials_but_not_mint_them(domain):
    verifier = domain.circle_verifier
    cred = domain.issue("agent-1", SCOPE)

    assert verifier.can_sign() is False
    assert verify_credential(verifier, cred)


def test_domain_exposes_its_signer_and_the_matching_public_verifier(domain, signer):
    assert domain.circle_signer is signer
    assert domain.circle_verifier.public_ref == signer.public_ref


def test_tampering_with_the_scope_fails_verification(domain):
    cred = domain.issue("agent-1", SCOPE)
    widened = Scope(allowed_actions=frozenset({"delete_files"}), may_spawn=True)
    forged = Credential(cred.agent_id, widened, cred.issuer_ref, cred.issued_at, cred.signature)

    assert domain.verify(cred)  # the original is still fine
    assert not domain.verify(forged)
    assert not verify_credential(domain.circle_verifier, forged)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda c: dataclasses.replace(c, agent_id="agent-2"), id="agent-id"),
        pytest.param(lambda c: dataclasses.replace(c, issued_at=c.issued_at + 3600), id="issued-at"),
        pytest.param(lambda c: dataclasses.replace(c, issuer_ref="hybrid:deadbeef"), id="issuer"),
        pytest.param(lambda c: dataclasses.replace(c, signature=c.signature.split(":")[0] + ":AAAA"), id="signature"),
    ],
)
def test_changing_any_signed_field_fails_verification(domain, mutate):
    forged = mutate(domain.issue("agent-1", SCOPE))

    assert not domain.verify(forged)
    assert not verify_credential(domain.circle_verifier, forged)


def test_credential_from_another_circle_is_rejected(domain):
    foreign = TrustDomain(new_signer()).issue("agent-1", SCOPE)

    assert not domain.verify(foreign)
    assert not verify_credential(domain.circle_verifier, foreign)


def test_credentials_are_immutable(domain):
    cred = domain.issue("agent-1", SCOPE)

    with pytest.raises(dataclasses.FrozenInstanceError):
        cred.agent_id = "someone-else"


def test_trust_domain_refuses_a_verify_only_handle():
    with pytest.raises(ValueError, match="signing authority"):
        TrustDomain(new_signer().verifier())


# ------------------------------------------------------------------------- scope
def test_default_scope_grants_nothing():
    scope = Scope()

    assert not scope.permits_action("read_logs")
    assert not scope.permits_host("example.com")
    assert not scope.permits_path("/var/log/app/today.log")
    assert scope.may_spawn is False


def test_scope_permits_exactly_what_it_lists():
    assert SCOPE.permits_action("read_logs")
    assert not SCOPE.permits_action("delete_files")
    assert SCOPE.permits_path("/var/log/app/today.log")
    assert not SCOPE.permits_path("/etc/passwd")


def test_scope_host_matching_is_exact_or_a_true_subdomain():
    scope = Scope(allowed_hosts=frozenset({"example.com"}))

    assert scope.permits_host("example.com")
    assert scope.permits_host("api.example.com")
    assert not scope.permits_host("evilexample.com")
    assert not scope.permits_host("example.com.evil.net")


def test_scope_canonical_form_ignores_insertion_order_but_not_content():
    a = Scope(allowed_actions=frozenset({"b", "a"}), allowed_hosts=frozenset({"y.com", "x.com"}))
    b = Scope(allowed_actions=frozenset({"a", "b"}), allowed_hosts=frozenset({"x.com", "y.com"}))

    assert a.canonical() == b.canonical()
    assert Scope(may_spawn=True).canonical() != Scope().canonical()


def test_scope_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        SCOPE.may_spawn = True

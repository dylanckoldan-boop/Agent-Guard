"""Pluggable signers and a hash-chained, tamper-evident audit log.

Two ideas live here, both load-bearing for the mesh:

**Asymmetric by default, so a watcher can verify without being able to forge.**
A sentinel that can *verify* a revocation but could also *mint* one is a single
point of compromise — a hijacked sentinel could forge an "all-clear" and blind
the web, or forge revocations and turn the registry into a denial-of-service
weapon. So the circle authority holds a private :class:`Signer`; every sentinel
holds only its public :meth:`Signer.verifier`. The default scheme is a hybrid
**ML-DSA-65 (FIPS 204) + Ed25519** signature (valid only if *both* component
signatures verify, so it stands as long as either algorithm is unbroken),
falling back to Ed25519, then to an HMAC signer that needs no third-party
library so the simulation runs anywhere. Signing sits behind one interface, so
the scheme can change without touching callers — the crypto-agility property.

**A hash-chained audit that breaks under tampering.** Each entry binds to its
predecessor through a SHA-256 chain; any edit, deletion or reorder breaks
verification. The chain head can additionally be PQ-signed, so an auditor can
prove both *integrity* (nothing was altered) and *origin* (it came from this
Agent Guard). This is the same mechanism as the companion Cryptomigrate
project's attestation log.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

try:  # strong classical signatures — present wherever `cryptography` is installed
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _HAVE_ED25519 = True
except Exception:  # pragma: no cover - exercised only on minimal installs
    _HAVE_ED25519 = False

try:  # post-quantum signatures — present on recent `cryptography` builds
    from cryptography.hazmat.primitives.asymmetric import mldsa

    _HAVE_MLDSA = True
except Exception:  # pragma: no cover
    _HAVE_MLDSA = False


class SignatureError(ValueError):
    pass


@runtime_checkable
class Signer(Protocol):
    """A thing that can sign and verify. The private half may be absent
    (a verify-only handle distributed to sentinels)."""

    scheme: str

    @property
    def public_ref(self) -> str: ...
    def can_sign(self) -> bool: ...
    def sign(self, message: bytes) -> str: ...
    def verify(self, message: bytes, signature: str) -> bool: ...
    def verifier(self) -> Signer: ...
    def public_bytes(self) -> bytes: ...


# --------------------------------------------------------------------------- HMAC
class HMACSigner:
    """Symmetric fallback (stdlib only). Models a single trust circle that
    shares a key: anyone who can verify can also sign, so its ``verifier`` is
    not a true read-only handle. Sufficient to prove an *outsider* cannot forge
    a revocation, and it keeps Agent Guard runnable with no third-party crypto.
    """

    scheme = "HMAC-SHA256"

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    @property
    def public_ref(self) -> str:
        return "hmac:" + hashlib.sha256(self._key).hexdigest()[:16]

    def can_sign(self) -> bool:
        return True

    def sign(self, message: bytes) -> str:
        return "hmac:" + hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            return hmac.compare_digest(self.sign(message), signature)
        except Exception:
            return False

    def verifier(self) -> HMACSigner:
        return self  # symmetric: no separate public half

    def public_bytes(self) -> bytes:
        return hashlib.sha256(self._key).digest()


# ------------------------------------------------------------------------- Ed25519
class Ed25519Signer:
    scheme = "Ed25519"

    def __init__(self, private: ed25519.Ed25519PrivateKey | None, public: ed25519.Ed25519PublicKey) -> None:
        self._priv = private
        self._pub = public

    @classmethod
    def generate(cls) -> Ed25519Signer:
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(priv, priv.public_key())

    @property
    def public_ref(self) -> str:
        return "ed25519:" + hashlib.sha256(self.public_bytes()).hexdigest()[:16]

    def can_sign(self) -> bool:
        return self._priv is not None

    def sign(self, message: bytes) -> str:
        if self._priv is None:
            raise SignatureError("this is a verify-only handle")
        return "ed25519:" + base64.b64encode(self._priv.sign(message)).decode()

    def verify(self, message: bytes, signature: str) -> bool:
        if not signature.startswith("ed25519:"):
            return False
        try:
            self._pub.verify(base64.b64decode(signature[8:]), message)
            return True
        except Exception:
            return False

    def verifier(self) -> Ed25519Signer:
        return Ed25519Signer(None, self._pub)

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @classmethod
    def from_public_bytes(cls, raw: bytes) -> Ed25519Signer:
        return cls(None, ed25519.Ed25519PublicKey.from_public_bytes(raw))


# -------------------------------------------------------------------------- Hybrid
class HybridSigner:
    """ML-DSA-65 (FIPS 204) + Ed25519. A signature verifies only if *both*
    component signatures verify, so the scheme stays secure as long as either
    algorithm is unbroken."""

    scheme = "ML-DSA-65+Ed25519"
    _MLDSA_PUB = 1952

    def __init__(self, mldsa_priv, mldsa_pub, ed_priv, ed_pub) -> None:
        self._mldsa_priv = mldsa_priv
        self._mldsa_pub = mldsa_pub
        self._ed_priv = ed_priv
        self._ed_pub = ed_pub

    @classmethod
    def generate(cls) -> HybridSigner:
        mp = mldsa.MLDSA65PrivateKey.generate()
        ep = ed25519.Ed25519PrivateKey.generate()
        return cls(mp, mp.public_key(), ep, ep.public_key())

    @property
    def public_ref(self) -> str:
        return "hybrid:" + hashlib.sha3_256(self.public_bytes()).hexdigest()[:16]

    def can_sign(self) -> bool:
        return self._mldsa_priv is not None and self._ed_priv is not None

    def sign(self, message: bytes) -> str:
        if not self.can_sign():
            raise SignatureError("this is a verify-only handle")
        env = {
            "mldsa65": base64.b64encode(self._mldsa_priv.sign(message)).decode(),
            "ed25519": base64.b64encode(self._ed_priv.sign(message)).decode(),
        }
        return "hybrid:" + base64.b64encode(json.dumps(env).encode()).decode()

    def verify(self, message: bytes, signature: str) -> bool:
        if not signature.startswith("hybrid:"):
            return False
        try:
            env = json.loads(base64.b64decode(signature[7:]))
            self._mldsa_pub.verify(base64.b64decode(env["mldsa65"]), message)
            self._ed_pub.verify(base64.b64decode(env["ed25519"]), message)
            return True
        except Exception:
            return False

    def verifier(self) -> HybridSigner:
        return HybridSigner(None, self._mldsa_pub, None, self._ed_pub)

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        mldsa_raw = self._mldsa_pub.public_bytes_raw()
        ed_raw = self._ed_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return mldsa_raw + ed_raw

    @classmethod
    def from_public_bytes(cls, raw: bytes) -> HybridSigner:
        mldsa_pub = mldsa.MLDSA65PublicKey.from_public_bytes(raw[: cls._MLDSA_PUB])
        ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(raw[cls._MLDSA_PUB :])
        return cls(None, mldsa_pub, None, ed_pub)


def new_signer(scheme: str = "auto") -> Signer:
    """Create a fresh signing authority. ``auto`` picks the strongest scheme
    the environment supports — the crypto-agility default."""
    if scheme in ("auto", "hybrid") and _HAVE_MLDSA and _HAVE_ED25519:
        return HybridSigner.generate()
    if scheme == "hybrid":
        raise SignatureError("hybrid ML-DSA-65 requires a recent `cryptography` build")
    if scheme in ("auto", "ed25519") and _HAVE_ED25519:
        return Ed25519Signer.generate()
    if scheme == "ed25519":
        raise SignatureError("Ed25519 requires the `cryptography` package")
    if scheme == "auto":
        # 'auto' must fail closed, never silently downgrade to the symmetric HMAC
        # fallback: a shared-key signer cannot hand sentinels a verify-only handle,
        # so a single compromised sentinel could forge revocations or an all-clear.
        # HMAC stays available, but only when asked for by name (see AG-A09).
        raise SignatureError(
            "no asymmetric signer available; install `cryptography`, "
            "or select scheme='hmac' explicitly to accept the symmetric fallback"
        )
    return HMACSigner()


def verifier_from_public(public_ref: str, public_bytes: bytes) -> Signer:
    """Rebuild a verify-only handle from distributed public material."""
    if public_ref.startswith("hybrid:"):
        return HybridSigner.from_public_bytes(public_bytes)
    if public_ref.startswith("ed25519:"):
        return Ed25519Signer.from_public_bytes(public_bytes)
    return HMACSigner(public_bytes)  # symmetric: 'public' material is the key digest; verify-only is notional


# ------------------------------------------------------------------ key persistence
def _der(priv) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return base64.b64encode(raw).decode()


def serialize_signer(signer: Signer) -> dict:
    """Serialize a signing authority — *including its private half* — to a dict.

    The circle's keypair must survive a restart or every credential and audit
    signature from the previous run would become unverifiable (AG-A03). The
    result is written to an owner-only keystore by the caller."""
    if isinstance(signer, HMACSigner):
        return {"scheme": "hmac", "key": base64.b64encode(signer._key).decode()}
    if isinstance(signer, Ed25519Signer):
        if signer._priv is None:
            raise SignatureError("cannot persist a verify-only handle")
        return {"scheme": "ed25519", "der": _der(signer._priv)}
    if isinstance(signer, HybridSigner):
        if not signer.can_sign():
            raise SignatureError("cannot persist a verify-only handle")
        return {"scheme": "hybrid", "mldsa": _der(signer._mldsa_priv), "ed25519": _der(signer._ed_priv)}
    raise SignatureError("cannot serialize this signer type")


def deserialize_signer(data: dict) -> Signer:
    """Rebuild a signing authority from :func:`serialize_signer` output."""
    from cryptography.hazmat.primitives import serialization

    scheme = data.get("scheme")
    if scheme == "hmac":
        return HMACSigner(base64.b64decode(data["key"]))
    if scheme == "ed25519":
        priv = serialization.load_der_private_key(base64.b64decode(data["der"]), password=None)
        return Ed25519Signer(priv, priv.public_key())
    if scheme == "hybrid":
        mp = serialization.load_der_private_key(base64.b64decode(data["mldsa"]), password=None)
        ep = serialization.load_der_private_key(base64.b64decode(data["ed25519"]), password=None)
        return HybridSigner(mp, mp.public_key(), ep, ep.public_key())
    raise SignatureError(f"unknown signer scheme {scheme!r}")


# ----------------------------------------------------------------------- audit log
@dataclass
class AuditEntry:
    seq: int
    ts: float
    event: str
    data: dict
    prev_hash: str
    this_hash: str


class AuditLog:
    """Append-only, hash-chained, tamper-evident log.

    Two-audience by design: opaque to a triggering agent, transparent and
    attributable to the human circle that can read it. ``sign_head`` binds the
    current chain head with the circle's signer, so an auditor gets both
    integrity and origin.
    """

    GENESIS = "0" * 64

    def __init__(self, signer: Signer | None = None, path: Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._signer = signer
        # When a path is given the chain is durable: it is loaded on construction
        # and rewritten after every append, so the tamper-evident log survives a
        # restart (AG-A03). With no path the log is in-memory (the default used by
        # unit tests and transient callers).
        self._path = path
        if path is not None:
            self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        restored: list[AuditEntry] = []
        for e in raw:
            try:
                restored.append(
                    AuditEntry(e["seq"], e["ts"], e["event"], e["data"], e["prev_hash"], e["this_hash"])
                )
            except (KeyError, TypeError):
                return  # a corrupt log is discarded rather than crashing startup
        self._entries = restored

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps([asdict(e) for e in self._entries]), "utf-8")
            tmp.replace(self._path)
        except OSError:
            pass

    def _digest(self, seq: int, ts: float, event: str, data: dict, prev_hash: str) -> str:
        payload = json.dumps(
            {"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev_hash},
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def append(self, event: str, data: dict | None = None) -> AuditEntry:
        seq = len(self._entries)
        prev = self._entries[-1].this_hash if self._entries else self.GENESIS
        ts = time.time()
        data = data or {}
        entry = AuditEntry(seq, ts, event, data, prev, self._digest(seq, ts, event, data, prev))
        self._entries.append(entry)
        self._save()
        return entry

    def verify(self) -> tuple[bool, int]:
        """Return (ok, checked_up_to). ok is False at the first broken link."""
        prev = self.GENESIS
        for e in self._entries:
            if e.prev_hash != prev:
                return False, e.seq
            if self._digest(e.seq, e.ts, e.event, e.data, e.prev_hash) != e.this_hash:
                return False, e.seq
            prev = e.this_hash
        return True, len(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1].this_hash if self._entries else self.GENESIS

    def sign_head(self) -> str | None:
        """PQ-sign the current chain head, if a signing authority is present."""
        if self._signer is None or not self._signer.can_sign():
            return None
        return self._signer.sign(self.head.encode())

    def events(self, name: str | None = None) -> list[AuditEntry]:
        return [e for e in self._entries if name is None or e.event == name]

    def tail(self, n: int = 50) -> list[AuditEntry]:
        return self._entries[-n:]

    def __len__(self) -> int:
        return len(self._entries)


def self_test() -> bool:
    """Round-trip the default signer and prove the audit chain breaks under
    tampering. Used at startup / in diagnostics."""
    s = new_signer()
    v = s.verifier()
    sig = s.sign(b"agent-guard self-test")
    if not v.verify(b"agent-guard self-test", sig):
        return False
    if v.verify(b"tampered", sig):
        return False
    log = AuditLog(s)
    log.append("selftest.a", {"x": 1})
    log.append("selftest.b", {"x": 2})
    ok, _ = log.verify()
    if not ok:
        return False
    log._entries[0].data["x"] = 999  # tamper
    broken, _ = log.verify()
    return not broken

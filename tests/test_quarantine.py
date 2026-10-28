"""AES-256-GCM quarantine: encrypted at rest, hash-verified restore."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time

import pytest
from cryptography.exceptions import InvalidTag

from agent_guard.quarantine import Quarantine

PAYLOAD = b"#!/usr/bin/env python\nprint('rogue agent')\n" + bytes(range(256)) * 4


@pytest.fixture
def sample(tmp_path):
    f = tmp_path / "rogue_agent.py"
    f.write_bytes(PAYLOAD)
    return f


@pytest.fixture
def vault():
    return Quarantine()


@pytest.fixture
def restore_dir(tmp_path):
    d = tmp_path / "restored"
    d.mkdir()
    return d


def blob_path(vault, item):
    return vault._root / f"{item.item_id}.bin"


def test_all_state_lives_under_the_isolated_data_root(vault, tmp_path):
    assert vault._root == tmp_path / "AgentGuard" / "quarantine"
    assert (vault._root / "quarantine.key").is_file()


def test_added_file_is_listed_with_its_metadata(vault, sample):
    item = vault.add(str(sample), "agent", "reason")

    assert item in vault.list()
    assert len(vault) == 1
    assert item.original_path == str(sample)
    assert item.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert item.size == len(PAYLOAD)
    assert (item.agent_id, item.reason) == ("agent", "reason")


def test_list_shows_the_newest_item_first(vault, sample):
    older = vault.add(str(sample), "agent", "older", remove_original=False)
    time.sleep(0.02)  # comfortably above the clock resolution on every platform
    newer = vault.add(str(sample), "agent", "newer", remove_original=False)

    assert [i.item_id for i in vault.list()] == [newer.item_id, older.item_id]


def test_restore_recreates_identical_bytes(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")

    restored = vault.restore(item.item_id, str(restore_dir))

    assert restored == str(restore_dir / sample.name)
    assert (restore_dir / sample.name).read_bytes() == PAYLOAD


def test_restore_to_an_explicit_file_path(vault, sample, tmp_path):
    item = vault.add(str(sample), "agent", "reason")
    target = tmp_path / "renamed.bin"

    assert vault.restore(item.item_id, str(target)) == str(target)
    assert target.read_bytes() == PAYLOAD


def test_restore_never_overwrites_an_existing_file(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")
    existing = restore_dir / sample.name
    existing.write_bytes(b"precious")

    with pytest.raises(FileExistsError):
        vault.restore(item.item_id, str(restore_dir))

    assert existing.read_bytes() == b"precious"


def test_stored_blob_is_encrypted(vault, sample):
    item = vault.add(str(sample), "agent", "reason")

    blob = blob_path(vault, item).read_bytes()

    assert PAYLOAD not in blob
    assert b"rogue agent" not in blob
    assert len(blob) == 12 + len(PAYLOAD) + 16  # nonce + ciphertext + GCM tag


def test_every_item_gets_a_fresh_nonce(vault, sample):
    first = vault.add(str(sample), "agent", "once", remove_original=False)
    second = vault.add(str(sample), "agent", "twice", remove_original=False)

    assert first.item_id != second.item_id
    assert blob_path(vault, first).read_bytes() != blob_path(vault, second).read_bytes()


def test_corrupt_blob_cannot_be_restored(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")
    blob_path(vault, item).write_bytes(b"xx")

    with pytest.raises((InvalidTag, ValueError)):
        vault.restore(item.item_id, str(restore_dir))

    assert not (restore_dir / sample.name).exists()  # nothing half-written


def test_a_flipped_ciphertext_bit_fails_authentication(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")
    raw = bytearray(blob_path(vault, item).read_bytes())
    raw[20] ^= 0x01
    blob_path(vault, item).write_bytes(bytes(raw))

    with pytest.raises(InvalidTag):
        vault.restore(item.item_id, str(restore_dir))

    assert not (restore_dir / sample.name).exists()


def test_altered_recorded_hash_trips_the_integrity_check(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")
    index_file = vault._root / "index.json"
    index = json.loads(index_file.read_text("utf-8"))
    index[item.item_id]["sha256"] = "0" * 64
    index_file.write_text(json.dumps(index), "utf-8")

    with pytest.raises(ValueError, match="integrity"):
        Quarantine().restore(item.item_id, str(restore_dir))

    assert not (restore_dir / sample.name).exists()


def test_a_corrupt_index_does_not_prevent_startup(vault, sample):
    vault.add(str(sample), "agent", "reason")
    (vault._root / "index.json").write_text("{not json", "utf-8")

    reopened = Quarantine()

    assert len(reopened) == 0  # the listing is lost, but the guard still starts


def test_a_different_key_cannot_decrypt_the_store(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")
    (vault._root / "quarantine.key").write_bytes(os.urandom(32))

    with pytest.raises(InvalidTag):
        Quarantine().restore(item.item_id, str(restore_dir))


def test_unknown_item_id_is_a_key_error(vault, restore_dir):
    with pytest.raises(KeyError):
        vault.restore("does-not-exist", str(restore_dir))


def test_store_persists_across_instances(vault, sample, restore_dir):
    item = vault.add(str(sample), "agent", "reason")

    reopened = Quarantine()

    assert reopened.list() == [item]
    reopened.restore(item.item_id, str(restore_dir))
    assert (restore_dir / sample.name).read_bytes() == PAYLOAD


def test_quarantine_moves_the_original_by_default(vault, sample):
    # By default add() MOVES the file out of its old location so it can't run
    # from there; an opt-in copy leaves the original in place (AG-A07).
    kept = sample.parent / "kept.py"
    kept.write_bytes(PAYLOAD)
    vault.add(str(kept), "agent", "copied", remove_original=False)
    assert kept.exists()

    vault.add(str(sample), "agent", "moved")
    assert not sample.exists()


def test_adding_a_missing_file_fails_and_leaves_the_vault_empty(vault, tmp_path):
    with pytest.raises(FileNotFoundError):
        vault.add(str(tmp_path / "nope.bin"), "agent", "reason")

    assert len(vault) == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_key_file_is_owner_only(vault):
    mode = stat.S_IMODE((vault._root / "quarantine.key").stat().st_mode)

    assert mode == 0o600

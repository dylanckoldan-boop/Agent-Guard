"""The oversight mesh: quorum-gated consensus and the 'many doors' mix channel."""

from __future__ import annotations

import json

import pytest

from foldward.mesh import DEFAULT_SENTINELS, Consensus, Decision, MixChannel, Sentinel


# ------------------------------------------------------------------------ consensus
def test_decoy_contact_is_self_authorizing_and_waives_quorum():
    decision = Consensus().decide({}, decoy=True)

    assert isinstance(decision, Decision)
    assert decision.contain is True
    assert decision.weighted_risk == 100.0
    assert "quorum waived" in decision.rationale


def test_one_sentinel_with_low_risk_holds():
    decision = Consensus(quorum=2, threshold=60).decide({"reach": 20}, decoy=False)

    assert decision.contain is False
    assert decision.agreeing == 1
    assert decision.weighted_risk < 60
    assert decision.rationale.startswith("held")


def test_a_single_sentinel_cannot_force_containment_even_at_maximum_risk():
    decision = Consensus(quorum=2, threshold=60).decide({"reach": 100})

    assert decision.weighted_risk >= 60  # the risk threshold is cleared...
    assert decision.agreeing == 1
    assert decision.contain is False  # ...but one voice is not a quorum


def test_agreement_without_enough_risk_still_holds():
    decision = Consensus(quorum=2, threshold=60).decide({"identity": 20, "behaviour": 20})

    assert decision.agreeing == 2
    assert decision.contain is False


def test_quorum_and_risk_together_contain():
    decision = Consensus(quorum=2, threshold=60).decide({"identity": 100, "behaviour": 100})

    assert decision.contain is True
    assert decision.agreeing == 2
    assert "quorum" in decision.rationale


def test_quorum_is_tunable():
    assert Consensus(quorum=1, threshold=60).decide({"reach": 100}).contain is True


@pytest.mark.parametrize(("points", "contain"), [(49, False), (50, True), (51, True)])
def test_the_risk_threshold_is_inclusive(points, contain):
    solo = Consensus(sentinels=[Sentinel("solo", "identity", 1.0)], quorum=1, threshold=50)

    assert solo.decide({"identity": points}).contain is contain


@pytest.mark.parametrize(("agreeing", "contain"), [(1, False), (2, True), (3, True)])
def test_the_quorum_is_inclusive(agreeing, contain):
    votes = dict.fromkeys(("identity", "reach", "behaviour")[:agreeing], 100)

    assert Consensus(quorum=2, threshold=60).decide(votes).contain is contain


def test_unknown_kinds_and_non_positive_points_do_not_vote():
    decision = Consensus().decide({"bogus": 100, "reach": 0, "identity": -5})

    assert decision.agreeing == 0
    assert decision.weighted_risk == 0
    assert decision.contain is False


def test_weighted_risk_is_capped_at_one_hundred():
    everything = {"identity": 100, "reach": 100, "behaviour": 100, "tripwire": 100}

    assert Consensus().decide(everything).weighted_risk == 100.0


def test_custom_sentinels_are_honoured():
    only = Consensus(sentinels=[Sentinel("solo", "identity", 1.0)], quorum=1, threshold=50)

    assert only.decide({"identity": 60}).contain is True
    assert only.decide({"reach": 100}).contain is False


def test_default_sentinels_cover_the_four_kinds_and_the_tripwire_weighs_most():
    assert {s.kind for s in DEFAULT_SENTINELS} == {"identity", "reach", "behaviour", "tripwire"}
    assert max(DEFAULT_SENTINELS, key=lambda s: s.weight).kind == "tripwire"


def test_consensus_instances_do_not_share_their_sentinel_list():
    a = Consensus()
    a.sentinels.append(Sentinel("extra", "reach", 1.0))

    assert len(Consensus().sentinels) == len(DEFAULT_SENTINELS)


# ------------------------------------------------------------------------ mix channel
def _sizes(batch):
    return {len(frame) for frame in batch}


def _schema(frame):
    n = int.from_bytes(frame[:2], "big")
    return tuple(sorted(json.loads(frame[2 : 2 + n]).keys()))


def test_emit_pads_one_real_message_with_cover_traffic():
    channel = MixChannel(enabled=True, min_cover=3)

    batch = channel.emit({"kind": "vote", "agent": "pid:1", "risk": 50})

    assert len(batch) == 4  # 1 real + 3 cover
    assert all(isinstance(frame, bytes) for frame in batch)
    assert (channel.stats.real_emitted, channel.stats.cover_emitted, channel.stats.total) == (1, 3, 4)


def test_real_and_cover_frames_are_indistinguishable_on_the_wire():
    channel = MixChannel(enabled=True, min_cover=5)

    batch = channel.emit({"kind": "vote", "agent": "pid:1", "risk": 50})

    assert len(_sizes(batch)) == 1, "every frame must be the same size"
    assert not any(b"_cover" in frame for frame in batch), "no frame may mark itself as cover"
    assert {_schema(frame) for frame in batch} == {("agent", "kind", "risk")}, "cover apes the real schema"


def test_urgent_messages_bypass_mixing():
    channel = MixChannel(enabled=True, min_cover=3)

    batch = channel.emit({"k": 1}, urgent=True)

    assert len(batch) == 1
    assert (channel.stats.real_emitted, channel.stats.cover_emitted) == (1, 0)


def test_disabled_channel_emits_only_the_real_message():
    channel = MixChannel(enabled=False, min_cover=3)

    batch = channel.emit({"k": 1})

    assert len(batch) == 1
    assert (channel.stats.real_emitted, channel.stats.cover_emitted) == (1, 0)


def test_stats_accumulate_across_emissions():
    channel = MixChannel(enabled=True, min_cover=3)

    channel.emit({"n": 1})
    channel.emit({"n": 2}, urgent=True)
    channel.emit({"n": 3})

    assert channel.stats.real_emitted == 3
    assert channel.stats.cover_emitted == 6
    assert channel.stats.total == 9


@pytest.mark.parametrize("min_cover", [1, 3, 8])
def test_batch_size_is_one_real_plus_min_cover(min_cover):
    batch = MixChannel(enabled=True, min_cover=min_cover).emit({"k": 1})

    assert len(batch) == 1 + min_cover


def test_emit_does_not_mutate_the_record_it_was_given():
    record = {"k": 1}

    MixChannel().emit(record)

    assert record == {"k": 1}

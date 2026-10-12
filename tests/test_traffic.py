"""Traffic shaping: what the sizes and the timing are supposed to look like.

The claims worth testing are the ones an observer could otherwise call out: the
size distribution must not be the payload's own distribution, must not be one
fixed value, must stay inside the carrier limit, and must not cost more than it
has to.  Timing is tested for the same reason — a fixed delay is a beacon.
"""

from __future__ import annotations

import random
import statistics

import pytest
from nfvpn.framing.constants import HEADER_SIZE, MAX_PAYLOAD, TAG_SIZE
from nfvpn.traffic import DEFAULT_PROFILE, PROFILES, Shaper, get_profile, profile_names

OVERHEAD = HEADER_SIZE + TAG_SIZE


def test_the_default_profile_exists():
    assert DEFAULT_PROFILE in PROFILES
    assert get_profile(None).name == DEFAULT_PROFILE


@pytest.mark.parametrize("name", profile_names())
def test_every_profile_is_self_consistent(name):
    profile = get_profile(name)
    assert profile.name == name
    assert profile.buckets == tuple(sorted(profile.buckets))
    assert profile.buckets[0] >= 64
    assert profile.description
    assert profile.largest_bucket >= MAX_PAYLOAD // 2  # can carry a full record


def test_unknown_profiles_are_refused():
    with pytest.raises(ValueError, match="unknown shaping profile"):
        get_profile("turbo")


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("default", DEFAULT_PROFILE),
        ("none", "off"),
        ("fast", "off"),
        ("gaming", "low-latency"),
        ("low_latency", "low-latency"),
        ("LOW-LATENCY", "low-latency"),
        ("max", "paranoid"),
    ],
)
def test_aliases_resolve(alias, expected):
    assert get_profile(alias).name == expected


def test_padding_never_truncates():
    shaper = Shaper(get_profile("balanced"), random.Random(1))
    for length in range(0, 4000, 37):
        padded = shaper.padded_plaintext(length)
        assert padded >= length + 2, "the length prefix and the payload must both fit"
        assert HEADER_SIZE + padded + TAG_SIZE <= MAX_PAYLOAD + OVERHEAD + 4096


def test_a_full_record_still_fits():
    shaper = Shaper(get_profile("balanced"), random.Random(2))
    padded = shaper.padded_plaintext(MAX_PAYLOAD)
    assert padded >= MAX_PAYLOAD + 2


def test_sizes_land_in_a_bucket_window_and_no_wider():
    """The wire size is the size class plus bounded jitter, never the payload's.

    ``off`` is the control: with padding disabled every length maps to itself,
    which is exactly the signature the shaped profiles are there to remove.
    """
    unpadded = Shaper(get_profile("off"), random.Random(3))
    assert len({unpadded.padded_plaintext(length) for length in range(100, 140)}) == 40

    profile = get_profile("low-latency")
    shaper = Shaper(profile, random.Random(3))
    # Every payload that fits in the first bucket must land inside that bucket's
    # window, and a payload that needs a bigger bucket must not.
    first_bucket = profile.buckets[0]
    for length in range(1, first_bucket - OVERHEAD - 2):
        size = HEADER_SIZE + shaper.padded_plaintext(length) + TAG_SIZE
        assert first_bucket <= size <= first_bucket + profile.noise
    larger = HEADER_SIZE + Shaper(profile, random.Random(3)).padded_plaintext(first_bucket) + TAG_SIZE
    assert larger >= profile.buckets[1], "a payload that no longer fits must move up"


def test_sizes_are_not_one_fixed_value_either():
    """A single size is a signature of its own, so the profile must spread."""
    shaper = Shaper(get_profile("balanced"), random.Random(4))
    sizes = {shaper.padded_plaintext(length) for length in range(0, 4000)}
    assert len(sizes) > 20


def test_the_size_to_payload_map_is_not_invertible():
    """An observer seeing a size must not learn a single payload length."""
    profile = get_profile("balanced")
    overhead = 2  # the plaintext length prefix
    ranges = {}
    for length in range(1, 3000):
        low, high = random.Random(0), random.Random(0)
        low.randrange = lambda _n: 0  # type: ignore[method-assign]
        high.randrange = lambda n: max(n - 1, 0)  # type: ignore[method-assign]
        ranges[length] = (
            profile.padded_plaintext(length, low),
            profile.padded_plaintext(length, high),
        )
    for length, (low, high) in ranges.items():
        candidates = [other for other, (o_low, o_high) in ranges.items() if o_low <= high and o_high >= low]
        assert len(candidates) >= 8, f"payload {length} is nearly identifiable"
    assert overhead == 2


def test_padding_actually_pads():
    shaper = Shaper(get_profile("balanced"), random.Random(5))
    padded = shaper.padded_plaintext(1000)
    assert padded > 1002
    assert padded - 1002 <= get_profile("balanced").largest_bucket


def test_overhead_stays_proportionate_for_bulk_transfers():
    shaper = Shaper(get_profile("balanced"), random.Random(6))
    total_payload = 0
    total_wire = 0
    for _ in range(200):
        length = random.Random(7).randrange(200, MAX_PAYLOAD)
        padded = shaper.padded_plaintext(length)
        total_payload += length
        total_wire += HEADER_SIZE + padded + TAG_SIZE
    assert total_wire / total_payload < 1.25, "bulk overhead above 25% would be a bad default"


def test_the_off_profile_does_not_pad():
    shaper = Shaper(get_profile("off"), random.Random(8))
    for length in (1, 900, MAX_PAYLOAD - 3):
        assert shaper.padded_plaintext(length) == length + 2


@pytest.mark.parametrize("name", ["low-latency", "balanced"])
def test_profiles_that_promise_no_latency_add_none(name):
    shaper = Shaper(get_profile(name), random.Random(9))
    assert [shaper.delay() for _ in range(50)] == [0.0] * 50


def test_the_paranoid_profile_spreads_its_delays():
    shaper = Shaper(get_profile("paranoid"), random.Random(10))
    delays = [shaper.delay() for _ in range(500)]
    assert all(0.0 <= delay <= 0.062 for delay in delays)
    assert statistics.pstdev(delays) > 0.002, "a fixed delay is a beacon"
    assert min(delays) >= get_profile("paranoid").base_delay


def test_cover_traffic_is_scheduled_only_where_it_is_asked_for():
    assert get_profile("off").cover_interval is None
    assert get_profile("low-latency").cover_interval is None
    for name in ("balanced", "paranoid"):
        interval = get_profile(name).cover_interval
        assert interval is not None and interval > 0


def test_cover_intervals_vary():
    shaper = Shaper(get_profile("balanced"), random.Random(11))
    intervals = [shaper.cover_delay() for _ in range(200)]
    assert len(set(intervals)) > 100, "a metronome is its own fingerprint"
    assert all(interval is not None and interval >= 0.05 for interval in intervals)


def test_the_same_seed_gives_the_same_shape():
    """Determinism is what makes any of this testable at all."""
    first = [Shaper(get_profile("balanced"), random.Random(99)).padded_plaintext(n) for n in range(200)]
    second = [Shaper(get_profile("balanced"), random.Random(99)).padded_plaintext(n) for n in range(200)]
    assert first == second


def test_random_seeds_give_different_shapes():
    first = [Shaper(get_profile("balanced"), random.Random(1)).padded_plaintext(n) for n in range(50)]
    second = [Shaper(get_profile("balanced"), random.Random(2)).padded_plaintext(n) for n in range(50)]
    assert first != second


def test_a_profile_without_buckets_is_refused():
    from nfvpn.traffic.shaper import ShapingProfile

    with pytest.raises(ValueError):
        ShapingProfile(name="broken", buckets=())
    with pytest.raises(ValueError):
        ShapingProfile(name="unsorted", buckets=(200, 100))

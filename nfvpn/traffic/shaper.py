"""Traffic shaping: what our packets look like, and when they leave.

A tunnel is not merely "encrypted".  An observer that cannot read a byte still
learns a lot from *shapes*: the size of every message, the gaps between them,
and how both change when you load a web page versus when you sit still.  This
module decides those two things.

Sizes
-----
The shaper answers one question: "I must send N bytes of payload — how big
should the carrier message be?"  It picks the smallest configured bucket that
fits, then jitters the result, so the observed distribution has neither the
payload's own signature nor the tell-tale exactness of fixed-size padding.  The
only thing left for an observer is a size class, which is what any encrypted
protocol shows anyway.

Timing
------
``base_delay`` plus exponential jitter blurs the arrival process.  The default
profile adds no delay at all: this project exists to be *used* (playing a
browser game over it), and 20 ms of manufactured latency is a worse outcome
than a mildly informative timing signal.  Profiles exist so that the trade-off
is an explicit, documented choice rather than an accident.

Cover traffic
-------------
Idle tunnels are conspicuous: a connection that transfers nothing for five
minutes and then 300 KB in four seconds is a scripted transfer.  Profiles may
schedule PAD records during quiet periods, which costs a little bandwidth and
removes that pattern.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

__all__ = ["PROFILES", "ShapingProfile", "get_profile", "profile_names"]


@dataclass(frozen=True)
class ShapingProfile:
    """How records should look and how they should be spaced."""

    name: str
    #: Candidate carrier-message sizes, in bytes, *including* header and tag.
    buckets: tuple[int, ...]
    #: Additive uniform jitter, in bytes, applied on top of the chosen bucket.
    noise: int = 0
    #: Fixed delay before each record, in seconds.  Zero means "send now".
    base_delay: float = 0.0
    #: Mean of the exponential extra delay, in seconds.  Zero disables it.
    mean_jitter: float = 0.0
    #: Upper bound on any single delay, in seconds.
    max_delay: float = 0.0
    #: Mean seconds between cover records while the tunnel is idle.  ``None``
    #: disables cover traffic entirely.
    cover_interval: float | None = None
    #: Human-readable description, shown by `nfvpn doctor`.
    description: str = ""
    #: Empirically useful detail for the report: what this is meant to resemble.
    mimics: str = "generic TLS application data inside WebSocket frames"

    def __post_init__(self) -> None:
        if not self.buckets:
            raise ValueError("a shaping profile needs at least one size bucket")
        if tuple(sorted(self.buckets)) != self.buckets:
            raise ValueError("size buckets must be sorted ascending")
        if self.buckets[0] < 64:
            raise ValueError("a bucket below 64 bytes cannot hold header and tag")

    @property
    def largest_bucket(self) -> int:
        return self.buckets[-1]

    def padded_plaintext(self, payload_length: int, rng: random.Random) -> int:
        """Return the encrypted-plaintext length that sees ``payload_length`` bytes.

        The result is the observed carrier size minus the record header and the
        AEAD tag, so ``observed_size = HEADER_SIZE + padded_plaintext``.
        """
        from nfvpn.framing.constants import HEADER_SIZE, TAG_SIZE

        needed = payload_length + 2  # the u16 length prefix lives inside the AEAD
        overhead = HEADER_SIZE + TAG_SIZE
        target = next((b for b in self.buckets if b - overhead >= needed), None)
        if target is None:
            # Larger than every bucket: pad up to the smallest multiple of the
            # biggest bucket that fits, so huge transfers stay on the grid.
            multiple = math.ceil((needed + overhead) / self.largest_bucket)
            target = multiple * self.largest_bucket
        if self.noise:
            target += rng.randrange(self.noise + 1)
        return max(target - overhead, needed)

    def delay(self, rng: random.Random) -> float:
        """Seconds to wait before sending the next record."""
        if not self.base_delay and not self.mean_jitter:
            return 0.0
        extra = 0.0
        if self.mean_jitter:
            extra = rng.expovariate(1.0 / self.mean_jitter)
            if self.max_delay:
                extra = min(extra, self.max_delay)
        return self.base_delay + extra

    def cover_delay(self, rng: random.Random) -> float | None:
        """Seconds until the next cover record, or ``None`` if unscheduled."""
        if self.cover_interval is None:
            return None
        # Gamma-ish spread around the mean keeps the idle pattern from becoming
        # a metronome, which would be its own signature.
        return max(0.05, rng.expovariate(1.0 / self.cover_interval) / 2)


#: Buckets are deliberately not powers of two: a stream of exactly 1024-byte
#: messages is a signature, whereas a spread of 96/144/208/… is what TLS
#: application data actually looks like.
_COMMON_BUCKETS = (
    96, 144, 208, 304, 432, 512, 688, 1024, 1328, 1664, 2208, 2816,
    3584, 4688, 6144, 7984, 10240, 13312, 16432,
)

PROFILES: dict[str, ShapingProfile] = {
    "off": ShapingProfile(
        name="off",
        buckets=(16432,),
        noise=0,
        description="No padding, no delay, no cover traffic. Fastest, most visible.",
        mimics="whatever your traffic actually is",
    ),
    "low-latency": ShapingProfile(
        name="low-latency",
        buckets=(144, 304, 688, 1328, 2816, 6144, 13312, 16432),
        noise=48,
        description="Padding only, small buckets. Good for games; timing is unshaped.",
        mimics="a chatty TLS session",
    ),
    "balanced": ShapingProfile(
        name="balanced",
        buckets=_COMMON_BUCKETS,
        noise=64,
        cover_interval=20.0,
        description="Size classes plus sparse cover traffic. The default.",
    ),
    "paranoid": ShapingProfile(
        name="paranoid",
        buckets=_COMMON_BUCKETS,
        noise=96,
        base_delay=0.012,
        mean_jitter=0.008,
        max_delay=0.05,
        cover_interval=3.0,
        description="Also shapes timing and hides idle periods. Costs latency.",
        mimics="a steady, always-on background service",
    ),
}

DEFAULT_PROFILE = "balanced"


def profile_names() -> list[str]:
    """Every profile name, in a stable order."""
    return list(PROFILES)


def get_profile(name: str | None) -> ShapingProfile:
    """Look a profile up by name; ``None`` means the default."""
    key = (name or DEFAULT_PROFILE).strip().lower()
    # Accept the common aliases people actually type.
    aliases = {
        "default": DEFAULT_PROFILE,
        "none": "off",
        "fast": "off",
        "gaming": "low-latency",
        "low_latency": "low-latency",
        "lowlatency": "low-latency",
        "high": "paranoid",
        "max": "paranoid",
    }
    key = aliases.get(key, key)
    if key not in PROFILES:
        raise ValueError(
            f"unknown shaping profile {name!r}; expected one of {', '.join(PROFILES)}"
        )
    return PROFILES[key]


@dataclass
class Shaper:
    """A stateful wrapper: profile plus a deterministic RNG (for tests)."""

    profile: ShapingProfile = field(default_factory=lambda: PROFILES[DEFAULT_PROFILE])
    rng: random.Random = field(default_factory=lambda: random.Random())

    def padded_plaintext(self, payload_length: int) -> int:
        return self.profile.padded_plaintext(payload_length, self.rng)

    def delay(self) -> float:
        return self.profile.delay(self.rng)

    def cover_delay(self) -> float | None:
        return self.profile.cover_delay(self.rng)

    def pad_record_size(self) -> int:
        """Observed size of a pure cover record (no payload at all)."""
        from nfvpn.framing.constants import HEADER_SIZE, TAG_SIZE

        return HEADER_SIZE + TAG_SIZE + self.padded_plaintext(0)

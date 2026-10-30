"""Replay protection.

Every record carries a monotonically increasing 64-bit counter, and the counter
is also the AEAD nonce.  A record that was already delivered is useless to an
attacker, but *replaying* it is not: replaying an OPEN could make the relay dial
a host twice, and replaying a DATA record could duplicate user traffic.  So the
receiver keeps a sliding window and refuses anything it has already seen.

The window is implemented as one arbitrarily-large Python integer used as a
bitmask, which keeps the code to a handful of obviously-correct operations
instead of a hand-rolled ring buffer.
"""

from __future__ import annotations

from nfvpn.errors import ReplayError

__all__ = ["ReplayWindow"]


class ReplayWindow:
    """Sliding-window duplicate detector for 64-bit counters.

    ``size`` is how far behind the highest counter a record may still arrive and
    be accepted — the price of tolerating reordering is that very old records
    stop being distinguishable from replays, so they are rejected outright.
    """

    __slots__ = ("_bits", "_highest", "_size")

    def __init__(self, size: int = 4096) -> None:
        if size < 1:
            raise ValueError("replay window size must be positive")
        self._size = size
        self._highest = -1
        self._bits = 0

    @property
    def highest(self) -> int:
        """Highest counter accepted so far, or ``-1`` before the first record."""
        return self._highest

    @property
    def size(self) -> int:
        return self._size

    def reset(self) -> None:
        """Forget everything; used when the session switches keys."""
        self._highest = -1
        self._bits = 0

    def check_and_update(self, counter: int) -> None:
        """Record ``counter``, raising :class:`ReplayError` if it is not fresh.

        Raises:
            ReplayError: the counter was seen before, or is older than the window.
        """
        if counter < 0:
            raise ReplayError("negative record counter")
        if self._highest < 0:
            self._highest = counter
            self._bits = 1
            return

        if counter > self._highest:
            gap = counter - self._highest
            if gap >= self._size:
                # Jumping further than the window forgets everything: the older
                # bits describe counters that are now outside it, so they carry
                # no information.  Shifting would try to allocate ``gap`` bits -
                # one record with counter 10**12 is 125 GB of shift, which is a
                # MemoryError an authenticated peer could trigger on purpose.
                self._bits = 1
            else:
                self._bits = (self._bits << gap) | 1
            self._highest = counter
            self._trim()
            return

        offset = self._highest - counter
        if offset >= self._size:
            raise ReplayError(
                f"record counter {counter} is older than the {self._size}-record window"
            )
        if self._bits >> offset & 1:
            raise ReplayError(f"record counter {counter} was already delivered")
        self._bits |= 1 << offset

    def _trim(self) -> None:
        excess = self._bits.bit_length() - self._size
        if excess > 0:
            self._bits >>= excess

    def seen(self, counter: int) -> bool:
        """Whether ``counter`` is inside the window and already recorded."""
        if counter > self._highest or counter < self._highest - self._size:
            return False
        return bool(self._bits >> (self._highest - counter) & 1)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ReplayWindow(size={self._size}, highest={self._highest})"

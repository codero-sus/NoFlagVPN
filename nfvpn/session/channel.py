"""The secure channel: an authenticated record pipe with rekeying and shaping.

After the handshake both sides hold the same :class:`~nfvpn.core.keys.SessionKeys`.
Each side then has:

* a :class:`~nfvpn.framing.records.FrameWriter` pointed at its *own* direction
  key, with the record counter as the AEAD nonce,
* a :class:`~nfvpn.framing.records.FrameReader` pointed at the *peer's* key,
  with the replay window, and
* a sender task that pulls sealed records off a queue, waits the amount of time
  the shaping profile asks for, and hands them to the carrier.

Rekeying
--------
Either side starts a rekey when a generation gets old or busy.  The sender seals
a REKEY record under the current keys, then both sides derive the next
generation from the master secret; the peer does the same when the REKEY record
arrives.  Records that were already in flight under the old key still decrypt,
because the reader keeps the previous generation until it has seen
:data:`~nfvpn.framing.records.FrameReader.CATCH_UP_RECORDS` records under the new
one.  Both sides end up in lock-step without any extra round trip.

Cover traffic
-------------
When the shaping profile asks for it, the sender task emits PAD records during
quiet periods, so an idle tunnel does not look like a dead one.  Cover records
are shaped like everything else and are indistinguishable from data on the wire.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

from nfvpn.core.keys import SessionKeys
from nfvpn.errors import ProtocolError, TransportError
from nfvpn.framing.constants import MAX_PAYLOAD, RecordType
from nfvpn.framing.records import FrameReader, FrameWriter, Record
from nfvpn.traffic.shaper import Shaper

__all__ = ["ChannelStats", "SecureChannel", "SendQueueFullError"]

#: Rotate keys after this much traffic on one generation (1 GiB).
DEFAULT_REKEY_BYTES = 1 << 30

#: …or after this long, whichever comes first (15 minutes).
DEFAULT_REKEY_SECONDS = 900.0

#: How many sealed records may wait for the carrier before senders block.
DEFAULT_QUEUE_DEPTH = 512


class SendQueueFullError(TransportError):
    """The carrier cannot keep up; the caller should slow down or give up."""


@dataclass
class ChannelStats:
    """Counters worth showing a user."""

    records_sent: int = 0
    records_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    padding_records: int = 0
    rekeys: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def uptime(self) -> float:
        return time.monotonic() - self.started_at

    def summary(self) -> str:
        return (
            f"{self.bytes_sent / 1024:.0f} KiB up / {self.bytes_received / 1024:.0f} KiB down, "
            f"{self.records_sent} records out, {self.records_received} in, "
            f"{self.padding_records} cover, {self.rekeys} rekeys, "
            f"up {self.uptime:.0f}s"
        )


class SecureChannel:
    """Sealed records in both directions over one carrier connection."""

    def __init__(
        self,
        keys: SessionKeys,
        transport,
        *,
        initiator: bool,
        shaper: Shaper | None = None,
        cover_traffic: bool = True,
        rekey_bytes: int = DEFAULT_REKEY_BYTES,
        rekey_seconds: float = DEFAULT_REKEY_SECONDS,
        queue_depth: int = DEFAULT_QUEUE_DEPTH,
    ) -> None:
        self.keys = keys
        self.transport = transport
        self.initiator = initiator
        self.shaper = shaper
        self.cover_traffic = cover_traffic and shaper is not None
        self.rekey_bytes = rekey_bytes
        self.rekey_seconds = rekey_seconds

        outbound_key = keys.initiator_to_responder if initiator else keys.responder_to_initiator
        inbound_key = keys.responder_to_initiator if initiator else keys.initiator_to_responder
        self.writer = FrameWriter(outbound_key, shaper)
        self.reader = FrameReader(inbound_key)

        self.stats = ChannelStats()
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=queue_depth)
        self._sender_task: asyncio.Task[None] | None = None
        self._failure: BaseException | None = None
        self._generation_started = time.monotonic()
        self._generation_bytes = 0
        self._closed = False
        self._send_lock = asyncio.Lock()
        self._last_activity = time.monotonic()

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        """Start the sender task.  Safe to call once."""
        if self._sender_task is None:
            self._sender_task = asyncio.create_task(
                self._sender_loop(), name="nfvpn-channel-sender"
            )

    async def close(self) -> None:
        """Stop the sender task.  Does not close the carrier (the session owns it)."""
        self._closed = True
        if self._sender_task is not None:
            self._sender_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sender_task
            self._sender_task = None

    # -- sending -----------------------------------------------------------
    async def send(
        self,
        record_type: RecordType,
        stream_id: int,
        payload: bytes = b"",
        *,
        flags: int = 0,
        raw: bool = False,
    ) -> None:
        """Seal a record and queue it for transmission.

        ``raw=True`` bypasses framing entirely and puts ``payload`` on the wire as
        its own carrier message.  It exists for the handshake, which happens
        before there are any keys.
        """
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise TransportError("channel is closed")

        if raw:
            await self._enqueue(payload)
            return

        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError(
                f"payload of {len(payload)} bytes exceeds the {MAX_PAYLOAD}-byte record limit"
            )

        async with self._send_lock:
            if self._needs_rekey():
                await self._rotate_keys()
            frame = self.writer.encode(record_type, stream_id, payload, flags=flags)

        await self._enqueue(frame)
        self._generation_bytes += len(frame)

    async def _enqueue(self, frame: bytes) -> None:
        try:
            await self._queue.put(frame)
        except asyncio.QueueFull as exc:  # pragma: no cover - put() awaits instead
            raise SendQueueFullError("the send queue is full; the carrier is stalled") from exc
        except asyncio.CancelledError:
            raise

    async def flush(self) -> None:
        """Wait until everything queued has been handed to the carrier."""
        await self._queue.join()

    def _needs_rekey(self) -> bool:
        if self.rekey_bytes and self._generation_bytes >= self.rekey_bytes:
            return True
        return bool(self.rekey_seconds) and (
            time.monotonic() - self._generation_started >= self.rekey_seconds
        )

    async def _rotate_keys(self) -> None:
        """Advance to the next key generation (see the module docstring)."""
        self.keys = self.keys.rekey()
        outbound = (
            self.keys.initiator_to_responder if self.initiator else self.keys.responder_to_initiator
        )
        inbound = (
            self.keys.responder_to_initiator if self.initiator else self.keys.initiator_to_responder
        )

        rekey_record = self.writer.encode(RecordType.REKEY, 0, b"")
        await self._enqueue(rekey_record)

        self.writer.rotate(outbound)
        self.reader.rotate(inbound, keep_previous=True)
        self._generation_started = time.monotonic()
        self._generation_bytes = 0
        self.stats.rekeys += 1

    # -- receiving ---------------------------------------------------------
    async def receive(self) -> Record:
        """Return the next record from the carrier.

        Call this from exactly one task.  PAD records are consumed here — cover
        traffic exists for the observer, not for the application.

        Raises:
            TransportError: the carrier is gone.
            ProtocolError: the peer sent something that is not a record.
        """
        while True:
            message = await self.transport.receive_message()
            record = self.reader.decode(message)
            self.stats.records_received += 1
            self.stats.bytes_received += len(message)
            self._last_activity = time.monotonic()

            if record.type is RecordType.REKEY:
                self._apply_peer_rekey()
                continue
            if record.type is RecordType.PAD:
                continue
            return record

    def _apply_peer_rekey(self) -> None:
        """The peer advanced the key generation; follow it."""
        self.keys = self.keys.rekey()
        outbound = (
            self.keys.initiator_to_responder if self.initiator else self.keys.responder_to_initiator
        )
        inbound = (
            self.keys.responder_to_initiator if self.initiator else self.keys.initiator_to_responder
        )
        self.writer.rotate(outbound)
        self.reader.rotate(inbound, keep_previous=True)
        self._generation_started = time.monotonic()
        self._generation_bytes = 0
        self.stats.rekeys += 1

    # -- carrier plumbing --------------------------------------------------
    async def _sender_loop(self) -> None:
        """Drain the queue, applying shaping delays and filling idle periods."""
        try:
            while True:
                timeout = self._cover_timeout()
                try:
                    frame = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except (TimeoutError, asyncio.TimeoutError):
                    if self._cover_due():
                        await self._send_cover_record()
                    if self._needs_rekey():
                        async with self._send_lock:
                            if self._needs_rekey():
                                await self._rotate_keys()
                    continue

                try:
                    if self.shaper is not None:
                        delay = self.shaper.delay()
                        if delay:
                            await asyncio.sleep(delay)
                    await self.transport.send_message(frame)
                    self.stats.records_sent += 1
                    self.stats.bytes_sent += len(frame)
                    self._last_activity = time.monotonic()
                finally:
                    self._queue.task_done()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._failure = exc
            # Unblock anything waiting to send.
            with contextlib.suppress(Exception):
                self._queue.put_nowait(b"")

    def _cover_timeout(self) -> float | None:
        if not self.cover_traffic:
            return None
        delay = self.shaper.cover_delay() if self.shaper else None
        return None if delay is None else max(delay, 0.05)

    def _cover_due(self) -> bool:
        if not self.cover_traffic or self.shaper is None:
            return False
        interval = self.shaper.profile.cover_interval
        if interval is None:
            return False
        return (time.monotonic() - self._last_activity) >= interval

    async def _send_cover_record(self) -> None:
        async with self._send_lock:
            frame = self.writer.encode_pad()
        try:
            await self.transport.send_message(frame)
        except TransportError as exc:
            self._failure = exc
            return
        self.stats.records_sent += 1
        self.stats.bytes_sent += len(frame)
        self.stats.padding_records += 1
        self._last_activity = time.monotonic()

    # -- introspection -----------------------------------------------------
    @property
    def failure(self) -> BaseException | None:
        """Set when the sender task died; the session should then shut down."""
        return self._failure

    @property
    def pending(self) -> int:
        """Records waiting for the carrier."""
        return self._queue.qsize()

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity

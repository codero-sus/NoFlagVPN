"""Moving bytes between a tunnel stream and a real socket.

Both ends of NoFlagVPN need the same thing: given one :class:`~nfvpn.session.streams.Stream`
and one TCP connection, shovel bytes in both directions until either side stops,
then clean up so nothing is left half-open.  It is written once here because
getting it subtly wrong in two places is how connections leak.
"""

from __future__ import annotations

import asyncio
import contextlib

from nfvpn.errors import NoFlagVPNError, TransportError
from nfvpn.framing.constants import CloseReason

__all__ = ["PUMP_CHUNK", "pump_bidirectional"]

#: Read size for the socket → stream direction.
PUMP_CHUNK = 64 * 1024


async def pump_bidirectional(
    stream,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    limiter=None,
    close_reason: CloseReason = CloseReason.NORMAL,
) -> tuple[int, int]:
    """Pump between ``stream`` and the socket behind ``reader``/``writer``.

    Returns ``(bytes_from_socket, bytes_to_socket)``.  Cancellation (the caller
    closing the tunnel) propagates; a broken socket does not.
    """
    counters = {"up": 0, "down": 0}

    async def socket_to_stream() -> None:
        try:
            while True:
                chunk = await reader.read(PUMP_CHUNK)
                if not chunk:
                    break
                if limiter is not None:
                    await limiter.consume(len(chunk))
                await stream.send(chunk)
                counters["up"] += len(chunk)
        except (TransportError, NoFlagVPNError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(TransportError, NoFlagVPNError):
                await stream.close(close_reason)

    async def stream_to_socket() -> None:
        try:
            while True:
                chunk = await stream.receive()
                if chunk is None:
                    break
                if limiter is not None:
                    await limiter.consume(len(chunk))
                writer.write(chunk)
                await writer.drain()
                counters["down"] += len(chunk)
        except (TransportError, NoFlagVPNError, ConnectionError, OSError):
            pass
        finally:
            # Half-close so the peer sees a proper end of stream; a full close
            # here would truncate whatever it is still sending us.
            with contextlib.suppress(Exception):
                writer.write_eof()

    await asyncio.gather(socket_to_stream(), stream_to_socket(), return_exceptions=True)
    return counters["up"], counters["down"]

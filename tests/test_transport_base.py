"""The transport interface's accounting, lifecycle, and normalized errors."""
from __future__ import annotations

import pytest
from nfvpn.errors import TransportError
from nfvpn.transport.base import Transport, TransportInfo


class MemoryTransport(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.opened = 0
        self.closed = 0
        self.inbox = [b"incoming"]

    async def open(self) -> None:
        self.opened += 1
        self._closed = False

    async def close(self) -> None:
        self.closed += 1
        self._closed = True

    async def send_message(self, payload: bytes) -> None:
        self._note_sent(len(payload))

    async def receive_message(self) -> bytes:
        payload = self.inbox.pop(0)
        self._note_received(len(payload))
        return payload

    @property
    def info(self) -> TransportInfo:
        return TransportInfo("memory", "peer", False)


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (TransportInfo("ws", "relay:443", True), "ws → relay:443 [TLS]"),
        (TransportInfo("raw", "relay:9001", False, "length-prefixed"), "raw → relay:9001 [cleartext] (length-prefixed)"),
    ],
)
def test_transport_info_description_includes_security_and_optional_detail(info, expected):
    assert info.describe() == expected


async def test_transport_context_manager_opens_and_closes_the_carrier():
    transport = MemoryTransport()
    assert transport.is_open is True
    async with transport as entered:
        assert entered is transport
        assert transport.opened == 1
        await transport.send_message(b"out")
        assert await transport.receive_message() == b"incoming"
        assert transport.messages_sent == 1
        assert transport.bytes_sent == 3
        assert transport.messages_received == 1
        assert transport.bytes_received == 8
    assert transport.closed == 1
    assert transport.is_open is False


async def test_transport_context_manager_closes_after_an_exception():
    transport = MemoryTransport()
    with pytest.raises(RuntimeError, match="inside context"):
        async with transport:
            raise RuntimeError("inside context")
    assert transport.closed == 1
    assert transport.is_open is False


def test_wrap_error_preserves_transport_errors_by_identity():
    original = TransportError("already normalized")
    assert Transport._wrap_error(original, "ignored") is original


def test_wrap_error_gives_timeouts_a_stable_message():
    wrapped = Transport._wrap_error(TimeoutError("socket deadline"), "write failed")
    assert str(wrapped) == "write failed: timed out"


def test_wrap_error_keeps_the_original_exception_type_and_message():
    wrapped = Transport._wrap_error(OSError("broken pipe"), "carrier write failed")
    assert str(wrapped) == "carrier write failed: OSError: broken pipe"

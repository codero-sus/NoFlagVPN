"""Fuzzing the parsers that face untrusted bytes.

Everything here is deterministic - a fixed seed per test, so a failure is
reproducible rather than "it happened once in CI".  Each fuzz asserts one of
three properties:

1. **No unhandled exception.**  Whatever arrives, the error is one of ours (or a
   documented ``ValueError`` from a helper whose contract says so).  An
   ``IndexError`` from ``struct.unpack_from`` is a bug, not input validation.
2. **No false accept.**  Random bytes, and bit-flipped valid frames, must not
   decode into a record that carries attacker-chosen plaintext.
3. **No unbounded state.**  A hostile peer sending junk must not grow the replay
   window or the nonce cache without limit.
"""

from __future__ import annotations

import asyncio
import random
import string
import struct

import pytest
from nfvpn.core.keys import Identity, Member, MembershipStore, parse_psk
from nfvpn.detect.probe import ProbeReport, format_report
from nfvpn.errors import (
    AuthenticationError,
    ConfigError,
    EncodingError,
    NoFlagVPNError,
    ProtocolError,
    ReplayError,
    TransportError,
)
from nfvpn.framing.constants import RecordType
from nfvpn.framing.records import FrameReader, FrameWriter
from nfvpn.framing.replay import ReplayWindow
from nfvpn.server.egress import EgressPolicy, resolve_and_authorize
from nfvpn.session.handshake import (
    HANDSHAKE_SIZE,
    HandshakeMessage,
    HandshakeResponder,
    SeenNonceCache,
)
from nfvpn.tokens import decode_invite
from nfvpn.transport import Endpoint
from nfvpn.transport.websocket import read_frame

SEED = 20261013
ITERATIONS = 400

KEY = bytes(range(32))
PSK = parse_psk("s7_SKalwmOc3WEsuA6bjyejEPW8a7t3VUpMZ5R83E-w")


def rng() -> random.Random:
    return random.Random(SEED)


def noise(source: random.Random, size: int) -> bytes:
    return bytes(source.getrandbits(8) for _ in range(size))


# --------------------------------------------------------------------------- #
# the frame layer
# --------------------------------------------------------------------------- #
def test_random_bytes_never_decode_into_a_record():
    reader = FrameReader(KEY)
    source = rng()
    accepted = 0
    for _ in range(ITERATIONS):
        frame = noise(source, source.randrange(0, 600))
        try:
            reader.decode(frame)
            accepted += 1
        except (ProtocolError, AuthenticationError, ReplayError):
            pass
    # The chance of a random frame authenticating is 2^-128; anything above zero
    # means the tag check is not being reached.
    assert accepted == 0


def test_flipping_any_bit_of_a_valid_frame_breaks_it():
    """The tag covers the header and the ciphertext, so no tamper survives."""
    writer = FrameWriter(KEY)
    frame = bytearray(writer.encode(RecordType.DATA, 7, b"payload that matters"))
    source = rng()
    for _ in range(ITERATIONS):
        mutated = bytearray(frame)
        bit = 1 << source.randrange(8)
        position = source.randrange(len(mutated))
        mutated[position] ^= bit
        reader = FrameReader(KEY)
        try:
            reader.decode(bytes(mutated))
            raise AssertionError(f"a bit flip at byte {position} still decoded")
        except (ProtocolError, AuthenticationError, ReplayError):
            pass


def test_a_replayed_record_is_refused_the_second_time():
    writer = FrameWriter(KEY)
    frame = writer.encode(RecordType.DATA, 1, b"hello")
    reader = FrameReader(KEY)
    reader.decode(frame)
    with pytest.raises(ReplayError):
        reader.decode(frame)


def test_truncated_frames_are_refused_with_our_own_error():
    writer = FrameWriter(KEY)
    frame = writer.encode(RecordType.DATA, 1, b"hello")
    for length in range(len(frame)):
        with pytest.raises((ProtocolError, AuthenticationError)):
            FrameReader(KEY).decode(frame[:length])


def test_an_absurd_length_prefix_is_refused_before_any_allocation():
    header = struct.pack(">BBHIQ", 1, 0, 0, 0, 0)
    # Long enough to authenticate, so the failure is integrity, not framing.
    with pytest.raises(AuthenticationError):
        FrameReader(KEY).decode(header + b"\x00" * 20)
    # Far past the maximum record size: rejected on the length alone.
    with pytest.raises(ProtocolError):
        FrameReader(KEY).decode(header + bytes(9_000_000))


def test_the_replay_window_stays_bounded_under_a_flood():
    window = ReplayWindow(64)
    for counter in range(0, 100_000, 7):
        window.check_and_update(counter)
    assert not window.seen(0), "a counter far behind the window is worth forgetting"


def test_a_huge_counter_jump_does_not_allocate_a_huge_bitmask():
    """One record with counter 10**12 used to raise MemoryError: the window
    shifted its bitmask by a trillion bits (125 GB) before trimming it."""
    window = ReplayWindow(4096)
    window.check_and_update(10**12)
    assert window.highest == 10**12
    # Everything before the jump is outside the window now, so it is refused...
    with pytest.raises(ReplayError):
        window.check_and_update(0)
    # ...and the next in-window counter still works.
    window.check_and_update(10**12 + 1)
    with pytest.raises(ReplayError):
        window.check_and_update(10**12 + 1)


def test_a_small_gap_still_remembers_the_records_inside_it():
    window = ReplayWindow(64)
    window.check_and_update(0)
    window.check_and_update(10)
    assert window.seen(0)
    with pytest.raises(ReplayError):
        window.check_and_update(0)


# --------------------------------------------------------------------------- #
# the handshake
# --------------------------------------------------------------------------- #
def test_handshake_messages_of_the_wrong_length_are_refused():
    source = rng()
    for _ in range(200):
        size = source.choice([0, 1, 111, 127, 129, 143, 256])
        with pytest.raises(ProtocolError):
            HandshakeMessage.unpack(noise(source, size))


def test_random_handshakes_are_refused_without_crashing():
    """A relay answering hostile INITs must always answer, never raise."""
    identity = Identity.generate("relay")
    membership = MembershipStore()
    membership.add(Member(name="client", public_key=Identity.generate("c").public_key, psk=PSK))
    responder = HandshakeResponder(identity, membership)
    source = rng()

    for _ in range(ITERATIONS):
        init = noise(source, HANDSHAKE_SIZE)
        answer = responder.answer(init)
        # The contract: every answer is 128 bytes and nothing is authorised.
        assert len(answer.message) == HANDSHAKE_SIZE
        assert answer.authorized is False
        assert answer.keys is None
        assert answer.reason


def test_a_real_handshake_still_works_after_all_that_junk(rig):
    """Sanity: the fuzzing above did not paper over a broken happy path."""
    assert rig.tunnel is not None


def test_the_nonce_cache_is_bounded():
    cache = SeenNonceCache(capacity=32)
    source = rng()
    for _ in range(1000):
        cache.check_and_add(noise(source, 32), noise(source, 16))
    assert len(cache) <= 32


# --------------------------------------------------------------------------- #
# text parsers
# --------------------------------------------------------------------------- #
def test_endpoint_parse_never_leaks_a_bare_value_error():
    source = rng()
    alphabet = string.printable + "é日本"
    for _ in range(600):
        text = "".join(source.choice(alphabet) for _ in range(source.randrange(0, 40)))
        try:
            endpoint = Endpoint.parse(text)
        except ConfigError:
            continue
        except ValueError as exc:  # a bare ValueError from int() would be a bug
            raise AssertionError(f"{text!r} raised {exc!r}") from exc
        assert 1 <= endpoint.port <= 65535
        assert endpoint.path.startswith("/")


def test_invite_tokens_that_are_not_tokens_are_refused_cleanly():
    source = rng()
    alphabet = string.printable
    for _ in range(600):
        body = "".join(source.choice(alphabet) for _ in range(source.randrange(0, 60)))
        try:
            decode_invite("nfvpn://" + body)
        except ConfigError:
            continue
        except NoFlagVPNError:
            continue
        raise AssertionError(f"nfvpn://{body!r} decoded as a valid invite")


def test_base64_decoding_refuses_junk_with_a_message():
    source = rng()
    for _ in range(400):
        text = "".join(source.choice(string.printable) for _ in range(source.randrange(0, 20)))
        try:
            from nfvpn.core.encoding import b64d

            if text.strip() == "":
                continue
            b64d(text)
        except EncodingError as exc:
            assert "base64url" in str(exc)
            # It is also a ValueError, so callers that catch that still work.
            assert isinstance(exc, ValueError)


# --------------------------------------------------------------------------- #
# the egress policy still decides, rather than exploding
# --------------------------------------------------------------------------- #
async def test_egress_always_decides_even_for_nonsense_hosts():
    policy = EgressPolicy()

    async def resolver(host, port, **kwargs):
        raise OSError("name resolution failed")

    source = rng()
    alphabet = string.ascii_letters + string.digits + ".-:%/\\ "
    for _ in range(300):
        host = "".join(source.choice(alphabet) for _ in range(source.randrange(0, 30)))
        port = source.choice([0, 1, 22, 25, 80, 443, 65535, 65536, -1, 70000])
        decision = await resolve_and_authorize(host, port, policy, resolver=resolver)
        assert isinstance(decision.allowed, bool)
        if not decision.allowed:
            assert decision.detail


# --------------------------------------------------------------------------- #
# the carrier's frame reader
# --------------------------------------------------------------------------- #
async def _serve_bytes(payload: bytes) -> asyncio.StreamReader:
    """A stream reader fed ``payload``, then closed."""
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


async def test_websocket_framing_refuses_malformed_frames():
    source = rng()
    for _ in range(150):
        data = noise(source, source.randrange(0, 40))
        reader = await _serve_bytes(data)
        try:
            await asyncio.wait_for(read_frame(reader), timeout=2)
        except TransportError:
            continue
        except Exception as exc:  # the point is to catch everything
            raise AssertionError(f"{data!r} raised {type(exc).__name__}: {exc}") from exc


async def test_websocket_control_frames_have_limits():
    # A control frame with a 200-byte payload is illegal (RFC 6455 caps it at
    # 125), and so is using the extended length form for one.
    frame = bytes([0x89, 126]) + struct.pack(">H", 200) + bytes(200)
    with pytest.raises(TransportError):
        await read_frame(await _serve_bytes(frame))
    # A 64-bit length with the high bit set is ill-formed ("length can never be
    # negative" is the point of the rule).  0x7F selects the 64-bit form.
    frame = bytes([0x82, 0x7F]) + b"\x80\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(TransportError):
        await read_frame(await _serve_bytes(frame))

    # And a plain zero-length binary frame is legal, so it must *not* raise.
    frame = await read_frame(await _serve_bytes(bytes([0x82, 0x00])))
    assert frame.payload == b""


def test_probe_reports_survive_hostile_headers():
    """Headers come from whoever answered; they end up in text and in --json."""
    report = ProbeReport(target="wss://relay.example/cdn", reachable=True)
    report.http_status = "HTTP/1.1 200 OK"
    report.http_headers = {"X-Odd": "\x00\x01\x1b[31mred\x1b[0m", "": ""}
    report.probe_reply_sizes = [128, 128, 128]
    report.findings()  # must not raise
    rendered = format_report(report)
    assert "relay.example" in rendered

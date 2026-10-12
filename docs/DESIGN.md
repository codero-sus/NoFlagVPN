# NoFlagVPN — protocol and design

This document is the reference for what the code actually does on the wire.  It
is deliberately specific: every number here appears somewhere in `nfvpn/`, and
`nfvpn/framing/constants.py` is the single place where they are defined.

- [1. What this is for](#1-what-this-is-for)
- [2. The threat model](#2-the-threat-model)
- [3. Architecture](#3-architecture)
- [4. The record layer](#4-the-record-layer)
- [5. Traffic shaping](#5-traffic-shaping)
- [6. Transports](#6-transports)
- [7. The handshake](#7-the-handshake)
- [8. Sessions, streams and rekeying](#8-sessions-streams-and-rekeying)
- [9. Refusals](#9-refusals)
- [10. Egress policy](#10-egress-policy)
- [11. What this does not protect against](#11-what-this-does-not-protect-against)

---

## 1. What this is for

A relay that is obviously a relay gets blocked.  The point of this project is
not to hide *what* you are sending — TLS does that — but to leave nothing about
the *shape* of the connection that says "VPN".

There are three ways a network operator finds a tunnel like this:

1. **Blacklists.** An IP address that many people use is a known relay.  Nothing
   at the protocol level fixes that; you run your own relay, on an address that
   looks like any other VPS.
2. **Active probing.** A scanner connects and tries to make the port contradict
   the story it tells.  A port that claims to be an HTTPS site but hangs up on
   anything except one specific magic string is a fingerprint.
3. **Traffic analysis.** Even when the bytes are unreadable, the sizes and
   timings are not.  A connection whose packets are always exactly 1024 bytes,
   or always at 20 Hz, is a machine.

NoFlagVPN is built around (2) and (3).  It carries its traffic in ordinary
WebSocket frames with the sizes and timings of ordinary traffic, and it answers
probes the way the web server it is pretending to be would.

## 2. The threat model

**Adversary.** Someone who can watch and modify every packet between client and
relay, and who can open connections to the relay themselves.  They have a
scanner, not a warrant: they decide what to block by what they can see and
measure cheaply, over the whole network, automatically.

**In scope.**

- Distinguishing the relay port from a normal WebSocket server by probing it.
- Identifying tunnel traffic by packet sizes or timing.
- Using a relay as a pivot into the relay operator's own network.
- Reading or modifying session traffic, including a man in the middle who has
  the relay's public key but not the pre-shared key.

**Out of scope.**

- Blocking the relay's IP address because it is a known endpoint (see §11).
- An adversary who has the pre-shared key.
- Compromising the endpoint: if your machine is owned, this does not help.
- Statistical analysis by someone who has traffic from *both* ends and the
  resources to correlate them over long periods.

## 3. Architecture

```
        application                     relay host                       the site
   ┌───────────────────┐          ┌────────────────────┐          ┌──────────────────┐
   │ browser / game    │          │  nfvpn serve       │          │  origin server   │
   │  SOCKS5 / HTTP    │          │                    │          │                  │
   │   ▼               │          │   ▼                │          │   ▲              │
   │ LocalProxy        │  ws/wss  │  Relay             │   TCP    │   │              │
   │   ▼               │ ───────▶ │   ▼                │ ───────▶ │   │              │
   │ Tunnel → Session  │          │  Session → egress  │          │   │              │
   └───────────────────┘          └────────────────────┘          └──────────────────┘
        SecureChannel                    SecureChannel
        (records, padding,               (same keys, mirrored
         replay window)                   directions)
```

Layers, bottom to top:

| Module | Responsibility |
| --- | --- |
| `nfvpn.core` | ChaCha20-Poly1305, X25519, HKDF, HMAC, key material. Pure Python, with an optional accelerated backend. |
| `nfvpn.framing` | The record layer: headers, AEAD, padding, replay window. |
| `nfvpn.traffic` | Shaping profiles: size classes, jitter, cover traffic. |
| `nfvpn.transport` | Carriers: WebSocket (RFC 6455), raw TCP with framing, optional TLS. |
| `nfvpn.session` | Handshake, encrypted channel, stream multiplexer. |
| `nfvpn.server` | The relay: accept sessions, run egress policy, dial targets. |
| `nfvpn.client` | The tunnel and the local SOCKS5/HTTP proxy. |
| `nfvpn.detect` | Probing an endpoint from outside; auditing a setup from inside. |
| `nfvpn.cli` | The `nfvpn` command. |

Everything above `nfvpn.core` is transport-agnostic.  `nfvpn.pump` connects a
stream to a byte pipe and is shared by client and server.

## 4. The record layer

### 4.1 Header

Every record begins with a 16-byte header, in network byte order:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     type      |     flags     |           reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          stream_id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            counter                            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`struct >BBHIQ`, so 1 + 1 + 2 + 4 + 8 = 16 bytes.  `type` is a `RecordType`
(DATA = 1, CTRL = 2, REKEY = 3, PAD = 4), `flags` is currently zero, `reserved`
must be zero, `stream_id` identifies a stream within the session, and `counter`
increments per record per direction.

**The header is authenticated, not encrypted.**  It is passed to the AEAD as
associated data, so nobody can change it without breaking the tag.  Keeping the
type in the clear costs nothing (it is one of four values and it is visible in
the size distribution anyway) and saves a round trip on rekey.

### 4.2 The frame

```
  header (16 B, authenticated)  ‖  AEAD(  u16 length ‖ payload ‖ zero padding  )  ‖  tag (16 B)
```

The nonce is the counter, left-padded to 12 bytes:

```
nonce = counter.to_bytes(8, "little") + b"\x00" * 4
```

The counter never repeats within a key generation — records are numbered
monotonically per direction — so the nonce is never reused.  The two directions
use different keys, so they may use the same counter values.

**The length lives inside the ciphertext.**  This is what makes padding worth
doing: an observer can measure the frame (that is unavoidable), but cannot learn
how many of those bytes were payload.  A payload of 1 byte and a payload of 200
bytes are the same size on the wire under the default profile, and there is no
field anywhere that distinguishes them.

The `u16` length prefix is required because the padded plaintext is a multiple
of a size class, not of the payload: without it there would be no way to know
where the payload ends and the padding begins.

Limits: `MAX_PAYLOAD` = 16384 bytes; a frame may not exceed
`MAX_PAYLOAD + 4096`.  Oversized frames are refused before allocation, so an
attacker cannot exhaust memory by claiming a large record.

### 4.3 Replay protection

Each direction keeps a sliding window (`ReplayWindow`, 4096 records) as one
arbitrary-precision integer used as a bitmap.  A record whose counter is already
set is dropped with `ReplayError`; a record more than 4096 behind the highest
counter is dropped too.  Out-of-order delivery inside the window is normal and
allowed.

Because the counter is authenticated, a replayed record is the only way to reuse
one — and that is exactly what the window refuses.  There is no nonce cache for
data records: the counter *is* the nonce, and the window is the cache.

### 4.4 Rekeying

Either side may rekey when a generation gets old (900 s) or busy (1 GiB).  The
sender seals a REKEY record under the *current* keys, then both sides derive the
next generation from the current master secret with HKDF.  Because the REKEY
record is itself a record, no extra round trip is needed and no interruption in
service appears: an observer sees nothing but a slightly unusual interval.

The reader keeps the previous key alongside the new one and tries both, so
records that were in flight when the peer rekeyed still open.  After
`CATCH_UP_RECORDS` (64) records under the new key the old one is dropped.  The
window is per generation.

Key separation: `SessionKeys` holds two traffic keys (one per direction) plus a
master secret for rekeying; the two directions never share a key stream.

## 5. Traffic shaping

A shaping profile (`nfvpn.traffic`) decides two things: how big the next record
is, and when to send it.

```
payload_length ──▶ smallest bucket that fits ──▶ + uniform(0, noise) ──▶ padded size
```

Buckets are deliberately *not* powers of two.  A stream of exactly-1024-byte
messages is its own signature; the default profile's classes are
96, 144, 208, 304, 432, 512, 688, 1024, 1328, 1664, 2208, 2816, 3584, 4688,
6144, 7984, 10240, 13312, 16432 — which is what TLS application data with a
browser on the other end actually looks like.

| Profile | Padding | Timing | Cover | Use |
| --- | --- | --- | --- | --- |
| `off` | none | none | no | maximum speed, maximum visibility |
| `low-latency` | size classes, small buckets | none | no | games (the default for interactive use) |
| `balanced` | full size classes | none | ~20 s idle | the default |
| `paranoid` | full size classes | 12 ms + exp(8 ms) | ~3 s idle | when being watched matters more than latency |

`balanced` and `low-latency` add **no** delay.  That is a deliberate choice: the
project exists to be used for things where 20 ms matters, and manufactured
latency is a worse outcome than a mildly informative timing signal.  Profiles
exist so that the trade-off is explicit rather than accidental.

Cover traffic (PAD records) fills idle periods.  An idle tunnel that transfers
nothing for five minutes and then 300 KB is scripted; one that dribbles a few
hundred bytes now and then looks like every chat application on the internet.
Intervals are drawn from an exponential distribution so the cover itself is not
a metronome.

Overhead: under `balanced`, bulk transfers pay about 4%; the worst case is a
one-byte request, which becomes a 96-byte frame.  `nfvpn doctor` measures both
on your machine and prints them.

## 6. Transports

### 6.1 WebSocket (default)

The carrier is a WebSocket connection, because a port serving WebSocket traffic
is a port serving video calls, dashboards, chat and games — blocking it is
expensive for the censor.

The implementation is deliberately literal about RFC 6455:

- Clients mask frames, servers never do, and the server closes on an unmasked
  client frame — that is what a real server does.
- No extensions are negotiated.  `permessage-deflate` is a fingerprint and a
  compression side channel.
- Control frames are never fragmented and never exceed 125 bytes.
- A non-upgrade request, a malformed upgrade, or an upgrade with a bad
  `Sec-WebSocket-Key` all get the same answer: nginx's default 404 page with a
  `Server: nginx` header.  The page is served even on the tunnel path.

Two encodings are available for record bytes: binary frames (default), or text
frames containing base64 — useful where a middlebox is suspicious of binary
WebSocket traffic.  Base64 costs 33% bandwidth and is a compatibility tool, not
a default.

### 6.2 Raw TCP and TLS

`tcp://` is a length-prefixed byte carrier for cases where WebSocket is not
available (a port forward, an SSH tunnel, a LAN).  It is honest about being a
tunnel and should not be used on a contested network.

`tls://` and `wss://` wrap the carrier in TLS 1.2+ with ALPN advertising
`h2,http/1.1`.  With `--tls-cert`/`--tls-key`, `nfvpn serve` speaks TLS itself;
with a `--ca-file` or plain `wss://`, the client verifies the relay's
certificate normally.  TLS-in-TLS is normal traffic now (every CDN does it), and
it means an observer sees a certificate for a real domain rather than a
self-signed one.

## 7. The handshake

One round trip, two fixed-size messages, and a confirmation record:

```
client                                                    relay
  │  INIT  (128 bytes)  ─────────────────────────────────────▶
  │                                                  verify MAC, clock,
  │                                                  nonce cache, allowlist
  │  ◀───────────────────────────────── RESP (128 bytes)
  │  verify MAC, pin check
  │  key schedule
  │  CONFIRM (a CTRL record)  ───────────────────────────────▶
```

### 7.1 Message layout

Both messages are exactly 128 bytes:

```
ver(1)  flags(1)  static(32)  ephemeral(32)  nonce(16)  timestamp(8)  padding(22)  mac(16)
       └──────────────── authenticated by the MAC ─────────────────────┘
```

- `static` — the sender's long-term X25519 public key.  The relay looks it up in
  its membership list; the client pins the relay's.
- `ephemeral` — a fresh X25519 public key per handshake, used for forward
  secrecy and then discarded.
- `nonce` — 16 random bytes, remembered by the relay (4096-entry cache) so a
  captured INIT cannot be replayed.
- `timestamp` — accepted within ±300 s.
- `padding` — random, so that no field position carries meaning.
- `mac` — HMAC-SHA256 truncated to 16 bytes, keyed by the pre-shared key,
  computed over the preceding 112 bytes with the label `b"nfvpn v1 init"` or
  `b"nfvpn v1 resp"`.

**Fixed size is the whole point.**  A prober who sends junk, a stranger with a
valid-looking key, a revoked member and a legitimate member all get a reply of
exactly 128 bytes, with a real MAC-shaped field.  There is nothing to weigh and
nothing to time.

### 7.2 Why a pre-shared key on top of public keys

Public keys decide *who* you are.  The PSK decides whether a given relay will
carry your traffic.  Without it, anyone who learns a relay's public key could
use it, and a seized relay would be usable by whoever seized it.  With it, a
relay's answer to a paying member and to a scanner is byte-for-byte the same
shape, and the relay never has to explain itself.

### 7.3 Key schedule

```
dh1 = X25519(initiator_ephemeral, responder_static)
dh2 = X25519(initiator_static,    responder_ephemeral)
dh3 = X25519(initiator_ephemeral, responder_ephemeral)
dh4 = X25519(initiator_static,    responder_static)
ikm = psk ‖ dh1 ‖ dh2 ‖ dh3 ‖ dh4
master = HKDF-SHA256(ikm, salt=SHA256(INIT ‖ RESP), info=b"nfvpn v1 handshake", 32)
```

from which two traffic keys and a rekey key are derived with distinct labels.
The order of `dh1`/`dh2` is role-dependent — the initiator computes
`(eph_a, static_b)` and the responder `(eph_b, static_a)` — so both sides pass
`initiator=True/False` and the concatenation is ordered identically.

Forward secrecy comes from the ephemeral keys: recovering a long-term key later
does not decrypt recorded sessions.  The PSK is mixed in first, so an attacker
who has the relay's static key but not the PSK derives a different master.

## 8. Sessions, streams and rekeying

A session is one encrypted channel plus a stream multiplexer.

- **Channel** (`nfvpn.session.channel`) — seals, frames and schedules records.
  A sender task coalesces writes so that a burst of stream data becomes one
  shaped record rather than a hundred tiny ones.
- **Streams** (`nfvpn.session.streams`) — RFC-9000-style flow control: each
  stream has a 256 KiB window; the receiver sends WINDOW control records as
  data is consumed, so a slow reader applies backpressure to the sender instead
  of dropping data.
- **Stream IDs** — `(counter << 1) | parity`, so the two sides never collide.
- **Control records** — OPEN, OPENED, CLOSE, WINDOW, PING, PONG, CONFIRM.
  Opening a stream carries the target as `host:port` plus a protocol byte, so
  the relay's egress policy sees a name, not a resolved address.
- **Limits** — 256 concurrent streams per session, 300 s idle timeout, 1 GiB or
  900 s per key generation.

The client resolves nothing.  A SOCKS5 request with a domain name is forwarded
as a domain name; the relay resolves it and applies the policy to *every*
address the name returns (§10).  This is what keeps DNS from being a side
channel, and what makes `--expose-lan` dangerous in a way the code refuses to
allow without authentication.

## 9. Refusals

Everything in this section exists so that "you were refused" cannot be
distinguished from "nothing here".

- **Same reply.** Malformed INIT, unknown key, revoked key, expired key, bad
  MAC, replayed nonce and wrong protocol version all produce a 128-byte
  response.  The response carries the relay's real static key, so it looks
  exactly like an acceptance to anyone without the PSK.
- **Same timing.** A refusal performs the same key-agreement work as an
  acceptance (`_burn_key_agreement_work`) and then lingers for up to 4 s
  (`DECOY_LINGER`) before closing, so measuring the answer's latency does not
  separate the two.
- **Same count.** Nothing is "skipped" on the refusal path: the reply is built,
  sent, and the connection is then treated like any other.
- **No error pages.** Any request that is not a valid upgrade is answered with
  the cover page.  A relay never sends anything that names its software, and a
  scanner cannot tell it from the web server whose 404 page it borrows.

`nfvpn probe` is the tool that measures this from outside: it does what a
scanner does and reports what came back.

## 10. Egress policy

A relay dials on behalf of its members, which makes it a potential pivot into
its own network.  The default policy refuses, before anything else:

- every non-global address: RFC 1918, loopback, link-local, CGNAT, multicast,
  reserved, and the IPv6 equivalents;
- `169.254.0.0/16`, which is where the cloud metadata service lives — the single
  most valuable target on a relay host;
- ports 25, 465, 587 and 2525, because an open relay on those gets the whole
  network's address space blacklisted;
- any name that resolves to *both* a public and a private address, which is the
  DNS-rebinding pattern;
- anything the operator adds with `--deny-network`/`--deny-port`.

The decision is made on every address a name resolves to, and the caller dials
exactly those addresses rather than resolving again — the second lookup is where
rebinding slips through.  `allow_private_literals` exists only so that the test
suite can reach a loopback origin, and the relay logs a warning when it is on.

## 11. What this does not protect against

Stated plainly, because a design document that only lists strengths is
marketing:

- **IP reputation.** Anyone can look up where your relay is hosted.  Running it
  on a large provider and moving it when it is blocked is the operational
  answer, not a protocol one.
- **A determined prober with a list of known relays** can still confirm a guess
  if it has the PSK or a seized relay.  This protocol makes confirmation
  *expensive*, not impossible.
- **Long-term correlation.** An observer who can see both ends of the link and
  correlate volumes over hours will find the tunnel.  Cover traffic raises the
  cost; it does not remove the signal.
- **Endpoint security.** The proxy is a local SOCKS5 port.  Anything on the
  machine can use it; `--expose-lan` extends that to the network and is
  therefore refused without `--proxy-auth`.
- **The PSK is a bearer token.** Whoever has it can use the relay.  Revocation
  stops new sessions, not running ones.

NoFlagVPN also cannot make using it *allowed*: evading a service's own detection
may violate that service's terms, and this document is not advice to do that.

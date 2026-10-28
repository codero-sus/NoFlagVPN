# NoFlagVPN

A personal tunnel that does not look like one.

NoFlagVPN carries your traffic to a relay you run yourself, inside ordinary
WebSocket frames, with the sizes and timings of ordinary web traffic.  To a
network that blocks VPNs by probing ports, it looks like the nginx box it is
pretending to be; to one that blocks them by recognising tunnel-shaped packets,
it looks like a browser talking to a CDN.

It is pure Python 3.10+, standard library only, with no install or build step for
normal use. An optional zipapp target creates a compact, relay-only executable
for deployment.

```console
$ nfvpn selftest
…
25/25 checks passed
```

## Install

```bash
git clone https://github.com/codero-sus/NoFlagVPN && cd NoFlagVPN
python3 -m nfvpn selftest        # works immediately: no dependencies
```

Add the package to your environment to get the `nfvpn` command:

```bash
pip install -e .                 # or: pip install -e '.[fast]' for acceleration
```

### Build a mini relay executable

For a small deployment that only needs to run the relay, build a compressed
Python zipapp. It bundles the NoFlagVPN package, has a relay-only command line,
and needs no pip install on the destination host:

```bash
python3 tools/build_mini_server.py --output dist/nfvpn-mini-server.pyz
# or: make mini-server MINI_SERVER_OUT=dist/nfvpn-mini-server.pyz
./dist/nfvpn-mini-server.pyz --help
./dist/nfvpn-mini-server.pyz --config relay.json
```

This is a self-executing `.pyz`, not a native machine-code binary: the target
still needs Python 3.10+ (use `python3 dist/nfvpn-mini-server.pyz ...` if its
platform does not launch `.pyz` files directly). The artifact is generated
locally and is ignored by Git.

To build a native executable for the current OS, install the optional packager
and run the make target:

```bash
make dev
.venv/bin/pip install -e '.[fast,build]'
make native-mini-server
```

The native build is OS-specific; use a Windows runner to build Windows, and a
macOS runner to build macOS. The release workflow builds each artifact on its
native GitHub runner.

For native Linux, Windows, and macOS binaries, plus a source archive and the
portable wheel, the release workflow builds assets on each OS and attaches them
to the GitHub Release when a `v*` tag is pushed. It also publishes `SHA256SUMS`.
Build only on a release tag after the change is merged; the native executable is
unsigned, so Windows SmartScreen or macOS Gatekeeper may show an origin warning.

The repository includes a starter `config.json` in its root. The native
executable and zipapp read `./config.json` by default; pass `--config PATH` to
select another file:

```bash
nfvpn-mini-server
# or, for the zipapp:
./dist/nfvpn-mini-server.pyz
```

The starter config binds all interfaces and references TLS certificate, private
key, identity, and membership files. Put the real files in place, protect
private keys and membership data, and restrict inbound traffic with your host
firewall.
Do not expose a relay without TLS and an explicit egress policy.

## Updating

```bash
./updater.sh            # Linux / macOS
updater.bat             # Windows
python updater.py       # any of them; identical behaviour
```

It fast-forwards the checkout, tells you what changed, and reinstalls the
console script if `pyproject.toml` moved.  Useful flags: `--check` (report
whether an update exists, exit `10` if it does), `--force` (stash local changes
and update anyway), `--branch`, `--dry-run`, `--quiet`.  `make update` does the
same thing.

Your keys are never involved: they live in the config directory
(`~/.config/nfvpn`, or `NFVPN_CONFIG_DIR`), not in the repository, so updating
cannot touch them.

`cryptography` is optional: if it is present, bulk encryption is roughly 70×
faster.  If it is not, a pure-Python ChaCha20-Poly1305 (verified against the
RFC 8439 vectors on every test run) does the work.

## Sixty seconds to a working tunnel

On the machine that will be the relay — a VPS, a home server, anything with a
public address:

```bash
nfvpn keygen --name relay                 # prints the relay's public key
nfvpn member add --name laptop --key <the laptop's public key>
nfvpn token --member laptop --relay wss://relay.example/cdn
```

On the laptop:

```bash
nfvpn keygen --name client --json         # copy `public_key` back to the relay
nfvpn connect --token 'nfvpn://…'         # a SOCKS5 + HTTP proxy on 127.0.0.1:8080
```

`--name` decides the file name, and the defaults that matter are `relay.key`
(what `serve` loads) and `client.key` (what `connect` loads).  If you use another
name, pass `--identity-file` to `connect` — it prints the exact command to
authorize the machine with when a relay refuses the handshake.

Point your browser (or game, or `curl`) at `socks5://127.0.0.1:8080` and you are
done.  The token carries the address, the relay's public key and the pre-shared
key in one string; it is a **secret** — treat it like a password.

For a throwaway look at the whole thing on one machine:

```bash
nfvpn demo        # a relay, a client and a test origin, wired together
make selftest     # ~30 end-to-end checks on loopback
```

## Commands

| Command | What it does |
| --- | --- |
| `nfvpn keygen` | Create this machine's long-term identity. |
| `nfvpn token` | Print one string that carries everything a client needs. |
| `nfvpn member {add,list,revoke,remove}` | Manage a relay's allowlist. |
| `nfvpn serve` | Run the relay. |
| `nfvpn-mini-server` | Relay-only entry point (also usable in the built zipapp). |
| `nfvpn connect` | Run the local SOCKS5/HTTP proxy. |
| `nfvpn probe TARGET` | Look at an endpoint the way a network scanner would. |
| `nfvpn selftest` | Run the whole stack on loopback and check every promise. |
| `nfvpn doctor` | Check this machine's setup and traffic shape. |
| `nfvpn demo` | Start a relay and a client locally, with a test origin. |
| `nfvpn version` | Version, Python, crypto backend. |

Useful flags:

- `nfvpn serve --tls-cert cert.pem --tls-key key.pem` — serve real TLS. Clients
  offer browser-like `h2,http/1.1` ALPN, while the relay selects `http/1.1`
  because it does not implement HTTP/2. `--disable-tls` is not a thing; use TLS
  in production.
- `nfvpn serve --profile paranoid` — sparser timing and more cover traffic.
- `nfvpn serve --deny-network 10.0.0.0/8` — the private ranges are refused by
  default; this is for adding your own.
- `nfvpn connect --failover wss://backup.example/cdn` — try another relay when
  the first is unreachable.
- `nfvpn connect --proxy-auth user:pass --expose-lan` — share the proxy with
  your LAN, with authentication (required for a non-loopback bind).
- `nfvpn probe relay.example:443 --json` — machine-readable probe output.

Exit codes: `0` success, `1` the command ran and something was wrong, `2`
misuse or a bad configuration, `130` interrupted.

## Routing your traffic

The client is a SOCKS5 + HTTP CONNECT proxy on `127.0.0.1:8080` and the relay
dials the destination - there is no virtual network interface anywhere in this
design. So routing means getting your applications to use that proxy: one
browser (best DNS privacy), the system proxy setting (covers browsers and
Electron apps), a transparent redirector (covers every TCP app, needs root and
gives up remote DNS), or sharing it with your other devices. UDP cannot ride
this tunnel, and neither can ICMP.

[docs/ROUTING.md](docs/ROUTING.md) has the recipes, the load-bearing firewall
exclusions, and the honest limits.

## How it avoids being recognised

Three things give a tunnel away, and each one has an answer here.

**Probing.** A port that claims to be a website but hangs up on anything except
one magic string is a fingerprint.  Here, a scan gets nginx's 404 page with a
`Server: nginx` header; a malformed WebSocket upgrade gets the same page; a
correct upgrade that sends junk gets a well-formed, fixed-size reply that
reveals nothing, because every handshake refusal is byte-for-byte the same shape
and takes the same time as an acceptance.

**Packet sizes.** Padding inside the authenticated payload, chosen from size
classes that are not powers of two, so that a one-byte request and a 200-byte
request leave the same bytes on the wire — and the real length is inside the
ciphertext where nobody can read it.  `nfvpn doctor` measures the overhead on
your machine (about 4% on bulk transfers).

**Timing and idle periods.** The `paranoid` profile adds jittered delays and
sends cover traffic while idle, so a tunnel that is not doing anything still
looks like something that is.  The default profile adds no latency at all,
because a tunnel you cannot play over is a tunnel you will not use.

The full story, including what this does *not* protect against, is in
[docs/DESIGN.md](docs/DESIGN.md).

## Safety

- **The relay is closed by default.** It answers an empty allowlist by refusing
  every handshake in the same way it refuses a scanner.  `nfvpn member add` is
  what makes it a relay for someone.
- **The relay will not dial your private network.** Loopback, RFC 1918,
  link-local, CGNAT, multicast and the cloud metadata service (`169.254.169.254`)
  are refused before anything is dialled, and a name that resolves to both a
  public and a private address is refused outright.  That is what stops a relay
  from becoming a pivot into its own host.
- **The local proxy binds to loopback** unless you pass `--expose-lan`, which
  requires `--proxy-auth`.
- **Secrets stay at 0600.** Keys, membership files and configs are written
  owner-only, and `nfvpn doctor` warns when they are not.
- **Revocation is immediate for new sessions.** Run `nfvpn serve` under a
  service manager to get the same for existing ones, and use `--profile
  paranoid` on a network where you expect to be watched.

What this cannot do: it cannot make using it permitted.  Evading a service's own
detection is between you and that service's terms.

## Development

```bash
make venv && make dev          # .venv with pytest, ruff, mypy, cryptography
make check                     # lint + typecheck + tests
make selftest                  # the end-to-end loopback suite
make update                    # pull the latest code into this checkout
python tools/gen_chacha.py --check   # the generated ChaCha kernels are in sync
```

Layout:

```
nfvpn/core       crypto: ChaCha20-Poly1305, X25519, HKDF, keys
nfvpn/framing    the authenticated record layer
nfvpn/traffic    shaping profiles: sizes, jitter, cover traffic
nfvpn/transport  carriers: WebSocket, raw TCP, TLS
nfvpn/session    handshake, encrypted channel, streams
nfvpn/server     the relay and its egress policy
nfvpn/client     the tunnel and the local proxy
nfvpn/detect     probing from outside, auditing from inside
nfvpn/cli        the command line
```

`tests/` mirrors that layout.  The crypto is checked against the RFC 8439 and
RFC 7748 vectors, and every other test asserts a promise made in this README or
in `docs/DESIGN.md`.

## License

MIT.

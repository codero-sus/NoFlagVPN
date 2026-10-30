# Routing your traffic through the tunnel

NoFlagVPN has no virtual network interface. There is no TUN device, no kernel
module, no `nfvpn0` in `ip addr`. The client is a **SOCKS5 and HTTP CONNECT
proxy** on `127.0.0.1:8080`, and the relay is the side that dials the final
destination. "Route my traffic through it" therefore means: *get your
applications to send their TCP through that proxy.*

That single fact decides everything below. Four ways to do it, in increasing
order of coverage and cost:

| Route | Covers | Root? | Verified here |
|---|---|---|---|
| [A. Per-app](#a-per-app-the-best-fidelity) | one browser, one tool | no | yes |
| [B. System proxy setting](#b-the-system-proxy-setting) | apps that honour it | no | yes |
| [C. Transparent redirect](#c-transparent-whole-device-needs-root) | every TCP app | **yes** | recipe only, see note |
| [D. Share it with your LAN](#d-share-it-with-the-lan) | your other devices | no | yes |

Read [What this cannot do](#what-this-cannot-do) before you pick. It is short,
and it is the part people are surprised by.

---

## A. Per-app: the best fidelity

This is the route to prefer, not the fallback. Because the proxy never resolves
hostnames locally, names travel through the tunnel and are resolved by the
relay, so your ISP sees nothing and there is no local DNS leak. The whole-device
routes below are *worse* at this, not better.

**Firefox** — Settings → Network Settings → Manual proxy configuration: SOCKS
host `127.0.0.1`, port `8080`, SOCKS v5, and tick **"Proxy DNS when using
SOCKS5"**. That checkbox is the difference between "my traffic goes through the
tunnel" and "my traffic goes through the tunnel but my ISP still sees every
site I visit".

**Chrome / Chromium** — it uses the OS setting (route B) or a flag:

```bash
google-chrome --proxy-server="socks5://127.0.0.1:8080"
```

`socks5://` sends names to the proxy; `socks4://` would resolve locally.

**curl and friends** — mind the flag, they are two different behaviours:

```bash
curl --socks5-hostname 127.0.0.1:8080 https://example.com    # proxy resolves
curl --socks5          127.0.0.1:8080 https://example.com    # you resolve
curl          -x http://127.0.0.1:8080 https://example.com   # HTTP CONNECT
```

**Anything else that speaks SOCKS5** — point it at `127.0.0.1:8080`. HTTP
clients that only understand `CONNECT` work on the same port; the proxy reads
the first byte and picks the protocol.

---

## B. The system proxy setting

Every desktop honours a system-wide proxy for well-behaved applications, which
is usually all browsers and Electron apps (Slack, Discord, VS Code).

**Windows** — Settings → Network & Internet → Proxy → Manual proxy setup.
The UI is HTTP/HTTPS only; for SOCKS5 across WinINET apps:

```powershell
netsh winhttp set proxy proxy-server="socks=127.0.0.1:8080" bypass-list="<local>"
```

**macOS** — System Settings → Network → your connection → Details → Proxies →
SOCKS proxy, host `127.0.0.1`, port `8080`.

**GNOME** —

```bash
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.socks host '127.0.0.1'
gsettings set org.gnome.system.proxy.socks port 8080
gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"
```

**KDE** — System Settings → Network → Proxy → Manual, SOCKS5 as above.

Use a **PAC file** instead if you want only some traffic tunnelled, for example
work tools direct and everything else through the tunnel:

```javascript
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.internal.example.com")) return "DIRECT";
  return "SOCKS5 127.0.0.1:8080; DIRECT";   // the fallback is what makes it feel instant
}
```

The catch, and it is the reason route C exists: `SOCKS5` in a PAC file tells the
*app* to hand over the hostname, so DNS still follows route A. And any
application that ignores system proxy settings — most games, native clients, CLI
tools — goes direct and untouched, with no warning. If that matters, you want C.

---

## C. Transparent: whole device, needs root

Get this right and every TCP connection from the machine flows through the
tunnel without any application knowing. Get it wrong and you have built a loop,
so read the exclusions carefully.

**Why it takes two pieces.** netfilter can `REDIRECT` a connection to a local
port, but the application's SOCKS5 handshake does not exist any more — the
redirected socket arrives bare. Our proxy speaks SOCKS5 and HTTP; it does not
read `SO_ORIGINAL_DST`. So you need a **redirector** in between that asks the
kernel "where was this connection really going?", then speaks SOCKS5 to
`127.0.0.1:8080` on the application's behalf. [redsocks](https://github.com/darkk/redsocks)
is the standard one; this project is deliberately not that, and no NoFlagVPN
code is needed on this path. What matters is that our proxy accepts what
redsocks sends — an IPv4 literal with no hostname — which
`tests/test_proxy_compat.py` asserts.

> **Honest note on verification.** Routes A, B and D are exercised by this
> repository's tests and were run end to end. The recipe below needs netfilter,
> which is not available in the sandbox this was written in, so it is a
> carefully-assembled recipe rather than a tested one. The *proxy side* of it —
> IPv4-literal requests, clean refusal of UDP — is tested.

**redsocks**, `/etc/redsocks.conf`:

```
base {
    log_debug = off;
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = 127.0.0.1;
    port = 8080;             // your NoFlagVPN client proxy
    type = socks5;
}
```

**nftables rules** — `/etc/nftables.conf`, added to what is already there:

```
table ip nfvpn {
    chain output {
        type nat hook output priority -100; policy accept;

        meta oif "lo" return                                   # keep loopback alone
        ip daddr <RELAY_IP> tcp dport <RELAY_PORT> return       # the tunnel's own connection
        tcp dport { 8080, 12345 } return                        # the proxy and the redirector
        meta skuid redsocks return                              # redsocks' own dial
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return  # LAN stays local
        tcp dport { 80, 443 } redirect to :12345
    }
}
```

Three exclusions are load-bearing. Leave out the relay's address and the
client's own connection to the relay gets redirected into the proxy, which sends
it through the tunnel to the relay, which dials the relay — a loop that looks
like a hung tunnel. Leave out `skuid redsocks` and redsocks' connection to the
proxy is itself redirected back into redsocks. Leave out loopback and everything
local breaks too.

Reload with `sudo nft -f /etc/nftables.conf && sudo systemctl restart redsocks`.

**The DNS story is worse here, and you should know why.** An application
resolves a name *before* it connects, so by the time netfilter sees the packet
the name is gone — only an address remains. Your resolver saw the name, and the
relay will dial the address you resolved, which may be a CDN node chosen for
your region. Put DNS on the tunnel as well and you get the worst of both
worlds: NoFlagVPN carries TCP only and refuses `UDP ASSOCIATE` by design (see
below), so `UDP:53` cannot ride the tunnel. The workable version of this is
DNS-over-HTTPS, which is TCP/443 and therefore already inside the redirect:

```bash
sudo resolvectl dns <interface> 1.1.1.1#cloudflare-dns.com    # systemd-resolved, DoH
```

If name-level privacy is the point of this for you, route A is the honest
answer. Transparent mode is for coverage, not for invisibility.

---

## D. Share it with the LAN

To let other devices on your network use *this* machine's tunnel, the client
has to listen beyond loopback, and it will not do that without a password —
an open proxy on a shared network is a gift to the neighbours:

```bash
nfvpn connect --token "$(cat token.txt)" \
  --expose-lan --proxy-auth neighbour:letmein
```

Then point the other device at `http://<this-machine-ip>:8080` (SOCKS5 and HTTP
CONNECT both work; many phones and tablets accept it in their Wi-Fi advanced
settings). The refusals are tested: wrong password gets SOCKS5's documented
`0x01` failure, and a client that cannot do username/password auth is refused
outright rather than allowed through (`tests/test_proxy_compat.py`).

The inverse arrangement — relay at home, you outside, reaching your own network
— is the same software with the roles swapped: run the relay inside the network
and give it `--allow-private` so it is allowed to dial `192.168.x.x`, then
connect from outside. That needs the relay to be reachable from outside, which
is the hard part, not the NoFlagVPN part.

---

## What this cannot do

**UDP.** Nothing UDP rides this tunnel: no QUIC, no game netcode that needs it,
no DNS. The proxy refuses `UDP ASSOCIATE` with SOCKS5's `0x07` rather than
pretending (`tests/test_proxy_compat.py::test_udp_associate_is_refused_with_the_documented_code`).
Browsers handle this gracefully — they try QUIC, notice, and fall back to TCP,
which is why a browser game like Bloxd.io works — but a UDP-only client simply
will not function through it.

**ICMP.** `ping` does not go through a proxy. Neither does `traceroute`.

**Kill switch.** If an application ignores proxy settings it goes direct, and
nothing here stops it. A real kill switch needs a firewall rule outside this
project, or a TUN device inside it — which would mean a kernel dependency this
design deliberately does not have.

**Anything on the relay's egress policy.** The relay refuses private
destinations and SMTP by default; `--allow-private` opens the former and is
labelled a test-rig option for a reason. And the address the world sees is the
*relay's*, so a datacenter IP with a bad reputation is still a datacenter IP
with a bad reputation — the tunnel hides your address, not the relay's.

**Legality.** What your traffic does is on you, and what the relay's address
does is on whoever runs it. Sites that forbid route-around tools in their terms
of service still forbid them.

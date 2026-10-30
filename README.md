# zray

English | [简体中文](docs/README.zh-CN.md)

A minimal [REALITY](https://github.com/XTLS/REALITY) client (VLESS +
`xtls-rprx-vision`) for home routers, written in Zig with no dependencies
beyond the Zig standard library.

It is built for the kind of box that has one or two slow cores, ~100 MB of
RAM and no FPU: a single thread, an `epoll` loop, and a fixed pool of
connection slots allocated up front. Memory use is decided at startup and does
not grow with traffic.

Reference deployment: Xiaomi AC2100 (MT7621, MIPS 1004Kc, soft-float,
ImmortalWrt 23.05): 802 KB static binary, 7.3 MB VSZ / ~2.2 MB RSS with
64 slots. Measured on that box against a REALITY server in Japan (~110 ms
RTT), pulling 50 MB through the tunnel:

| Path                                      | Throughput | zray CPU (one 1004Kc thread) |
|-------------------------------------------|-----------:|-----------------------------:|
| HTTPS, Vision switched to direct copy     | 9-10 MB/s  | ~17 %                        |
| HTTP, stays inside outer TLS (sw AES-GCM) | 1.5 MB/s   | ~98 %                        |
| 3 parallel HTTPS streams                  | 10 MB/s aggregate | ~55 %                 |

The same host fetched directly over the WAN, without the tunnel, does
1.4 MB/s: the ISP's international path is the slow part. HTTPS through the
tunnel is bound by the server link; HTTP, which cannot leave the outer TLS,
is CPU-bound, since software AES-GCM on this core tops out around 1.5 MB/s.
That is why Vision's direct copy matters here.

One kernel knob matters on a box like this: the default `net.ipv4.tcp_rmem`
ceiling with 128 MB of RAM is about 930 KB, which caps a single stream at
roughly window / RTT, about 1 MB/s at 190 ms. Raising the ceiling (for
example `net.ipv4.tcp_rmem = 4096 131072 4194304` in `/etc/sysctl.d/`)
lifted the HTTPS numbers above from ~1 MB/s to what the table shows. Do not
set `sock_buf` for this; it disables the kernel's autotuning and is clamped
by `net.core.rmem_max`.

![throughput on mir](docs/images/throughput-mir.png)

## What it does

- **TLS 1.3 client** written from scratch on top of `std.crypto`: key
  schedule, record layer, handshake state machine, certificate signature
  verification. Verified byte-for-byte against RFC 8448.
- **REALITY authentication**: ephemeral X25519 against the server public key,
  HKDF auth key, AEAD-sealed `session_id`, HMAC-SHA512 certificate check.
- **Chrome TLS fingerprint**: GREASE in cipher suites / groups / key share /
  versions / extensions, 15 Chrome cipher suites, per-connection extension
  shuffle, GREASE ECH, ALPS, `compress_certificate`, X25519MLKEM768 hybrid
  key share. JA4 `_b` and `_c` segments match current Chrome.
- **VLESS + XTLS Vision**: padding state machine, switch to direct copy once
  the inner TLS 1.3 handshake is seen, so bulk traffic is not double-encrypted.
- **Inbounds**: SOCKS5 (CONNECT and UDP ASSOCIATE) and transparent
  netfilter `REDIRECT` with `SO_ORIGINAL_DST`.
- **UDP** over XUDP (VLESS mux), full-cone, as xray does for Vision.
- **Zero-latency sniffing**: TLS SNI and HTTP `Host` are read from the first
  client bytes that arrive while the upstream handshake is still in flight,
  so the server sees a domain instead of an IP.

Not included, on purpose: TLS 1.2, session resumption, 0-RTT, certificate
decompression (we only *offer* `compress_certificate`; Go servers never use
it), TPROXY, SOCKS5 UDP fragmentation.

## Building

Requires Zig 0.17.0. Prebuilt binaries for mipsel / mips / aarch64 / armv7 /
x86_64 (all static musl) are attached to each tagged release; CI builds every
push (see .github/workflows/).

```sh
zig build test                                   # unit tests (host)
zig build --release                              # host binary -> zig-out/bin/zray

# cross-compile for a router
zig build --release -Dtarget=mipsel-linux-musl -Dcpu=mips32r2+soft_float -p zig-out/mipsel
zig build --release -Dtarget=aarch64-linux-musl -p zig-out/aarch64
zig build --release -Dtarget=x86_64-linux-musl  -p zig-out/x86_64
```

`--release` uses `ReleaseSmall`. The proxy service is Linux-only; the probe
below runs anywhere.

### Probe

`probe` performs one real handshake and one proxied HTTP(S) request without
starting the service. Useful for checking a server config or looking at the
negotiated parameters:

```sh
zig build probe -- <ip> <port> <sni> <public_key> [short_id|-] [uuid url]

zig build probe -- 203.0.113.5 443 example.com K5Ko4T...4G8 - \
    00000000-0000-0000-0000-000000000000 https://www.cloudflare.com/
```

Output includes the cipher suite and group chosen by the REALITY server,
whether the certificate HMAC verified, and bytes received through the tunnel.
Pointing the URL at `https://tls.peet.ws/api/all` shows the fingerprint the
inner connection presents.

## Configuration

`zray [config.json]` (default `./config.json`). See
[config.example.json](config.example.json) (REALITY) and
[config.example.tls.json](config.example.tls.json) (plain TLS).

| key | default | meaning |
|---|---|---|
| `listen` | `127.0.0.1:1080` | SOCKS5 inbound. `""` disables it. |
| `redirect` | `""` | Transparent inbound for `REDIRECT` rules. `""` disables it. At least one of `listen` / `redirect` must be set. |
| `sniff` | `true` | Replace the destination IP with the TLS SNI / HTTP Host when present. |
| `server` | ? | Upstream server hostname or IP (REALITY or plain TLS). Resolved once at startup. |
| `port` | `443` | |
| `bootstrap_dns` | `""` | Nameserver (`ip` or `ip:port`) asked directly over UDP to resolve `server` at startup, bypassing `/etc/resolv.conf`. Set it when the local resolver itself goes through the tunnel, so the two services do not wait on each other at boot. Falls back to the system resolver on failure. |
| `sni` | `server` | SNI sent in the ClientHello (the camouflage site). |
| `security` | `"reality"` | `"reality"` or `"tls"` (plain VLESS+TLS, see below). |
| `public_key` | ? | Server `publicKey` (base64url, as in the share link). Required with `security = "reality"`, rejected with `"tls"`. |
| `short_id` | `""` | Hex, up to 8 bytes. REALITY only. |
| `tls_verify` | ? | `security = "tls"` only, and then mandatory. Only `"none"` (no certificate verification, like `allowInsecure`) is implemented; `"ca"` and `"pin"` are reserved and rejected for now. |
| `uuid` | ? | VLESS user id. |
| `max_connections` | `128` | Connection slots. Each slot is ~92 KiB, allocated at startup. |
| `handshake_timeout_s` | `15` | TCP connect + TLS handshake deadline. |
| `idle_timeout_s` | `600` | Close a relay with no traffic in either direction. |
| `sock_buf` | `0` | `SO_SNDBUF` / `SO_RCVBUF` per socket; `0` leaves kernel defaults. |

The REALITY server checks the client's clock (timestamp inside the sealed
`session_id`). A router whose time is not synced will fail every handshake
with `CertificateRejected`.

### Plain VLESS + TLS (no REALITY)

```json
{
  "security": "tls",
  "tls_verify": "none",
  "server": "node.example.com",
  "uuid": "00000000-0000-0000-0000-000000000000"
}
```

With `security = "tls"`, zray performs a standard TLS 1.3 handshake instead:
a random `session_id`, no REALITY auth extension, and (with
`tls_verify = "none"`) no certificate chain verification, equivalent to
`allowInsecure`. That is enough to reach a plain VLESS + `xtls-rprx-vision`
over TLS endpoint, as offered by most commercial providers. `public_key` and
`short_id` must be absent in this mode and `sni` must match the name on the
server certificate. The REALITY-only `compress_certificate` extension is
suppressed so an upstream cannot compress certificates in a form this client
does not parse.

The mode is never inferred: a REALITY config with a missing or misspelled
`public_key` fails at startup instead of silently becoming plain TLS, and
unknown keys in the config are rejected. The startup log prints the mode in
use.

**Risk.** `tls_verify = "none"` accepts any certificate. Anyone on the path
(a hostile Wi-Fi, an ISP middlebox, a compromised router upstream) can
impersonate the server, obtain the VLESS `uuid`, and read or modify every
byte inside the tunnel. Use it only on paths you trust, or when you accept
that risk. Routers usually do not ship a usable CA bundle (`opkg install
ca-bundle` adds one), so CA (`"ca"`) and SPKI pinning (`"pin"`) verification
are planned as the safer alternatives.

## Deploying on OpenWrt

See [deploy/](deploy/) for a procd init script and a config template.

```sh
scp zig-out/mipsel/bin/zray root@router:/mnt/zray/zray
scp config.json             root@router:/mnt/zray/config.json
scp deploy/zray.init        root@router:/etc/init.d/zray
ssh root@router 'chmod 755 /etc/init.d/zray /mnt/zray/zray; chmod 600 /mnt/zray/config.json;
                 /etc/init.d/zray enable; /etc/init.d/zray start'
```

Transparent proxying needs an nft (or iptables) `redirect` rule feeding the
`redirect` port. A typical domain-based split uses a DNS resolver that writes
resolved IPs into an nft set and a rule such as:

```
table inet gfw {
    set iplist { type ipv4_addr; flags interval; }
    chain prerouting { type nat hook prerouting priority 0;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
    chain output     { type nat hook output priority filter;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
}
```

Make sure the REALITY server's own IP never ends up in that set, and that the
resolver used to look up `server` does not itself depend on the tunnel. If it
does (chinadns-ng or dnsmasq forwarding over DoT through zray), set
`bootstrap_dns` to a public nameserver so startup resolution never touches the
local resolver.

## Layout

```
src/
  main.zig            config, listeners, epoll main loop
  probe.zig           one-shot handshake / request tester
  tls/
    hello.zig         ClientHello serializer
    key_schedule.zig  TLS 1.3 key schedule (SHA-256 / SHA-384)
    record.zig        record layer, AEAD, per-record nonce
    handshake.zig     handshake message reassembly and parsing
    signature.zig     CertificateVerify signature check
    client.zig        sans-I/O handshake state machine (X25519, X25519MLKEM768)
    reality.zig       REALITY auth: session_id sealing, certificate HMAC
    fingerprint.zig   Chrome ClientHello parameters
    testdata/         RFC 8448 vectors (generated)
  proxy/
    vless.zig         VLESS request / response headers
    vision.zig        XTLS Vision padding state machine
    mux.zig           XUDP (Mux.Cool) frames
    socks5.zig        SOCKS5 greeting / CONNECT / UDP ASSOCIATE
    sniff.zig         TLS SNI and HTTP Host extraction
  linux/
    sys.zig           thin syscall wrappers (sockets, epoll, SO_ORIGINAL_DST)
    conn.zig          per-connection state machine and relay
deploy/               OpenWrt procd script and config template
tools/udptest.py      SOCKS5 UDP ASSOCIATE smoke test
```

Everything in `tls/` and `proxy/` is sans-I/O and unit tested
(`zig build test`); `linux/` is the only part that touches sockets.

## Status and known limits

- `server` is resolved once at startup; an IP change needs a restart. There is
  no connect backoff yet. See [TODO.md](TODO.md).
- UDP payloads above roughly 600 bytes may be dropped depending on the server's
  outbound; DNS works, QUIC generally does not.
- No log level control; every connection logs its lifecycle to stderr.

## License

[MIT](LICENSE).

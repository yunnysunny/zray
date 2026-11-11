# zray user guide

English | [简体中文](usage.zh-CN.md)

> A web version of this guide lives at [website/usage.html](../website/usage.html), styled like the official site and switchable between English and Chinese.

This is the **operator's guide**: which file to download, how to write the config, how to run it on a router after a reboot, and where to look when something breaks.

[README](../README.md) is the complete feature and configuration reference; [the chaining tutorial](chain-relay-exit.zh-CN.md) (Chinese) covers relay / exit chains separately. The three complement each other.

- [1. Is this for you?](#1-is-this-for-you)
- [2. Running in five minutes (SOCKS5)](#2-running-in-five-minutes-socks5)
- [3. Where the values come from: share links](#3-where-the-values-come-from-share-links)
- [4. Three ways to deploy](#4-three-ways-to-deploy)
- [5. Run it as a service](#5-run-it-as-a-service)
- [6. Tuning: spend the scarce CPU and RAM well](#6-tuning-spend-the-scarce-cpu-and-ram-well)
- [7. Troubleshooting](#7-troubleshooting)
- [8. Upgrading from v0.3](#8-upgrading-from-v03)
- [9. The two bundled test tools](#9-the-two-bundled-test-tools)

## 1. Is this for you?

zray is a **client**; nothing is deployed on the server side. You need three things:

| Need | Notes |
|---|---|
| A Linux box | The proxy service runs on Linux only: a router (OpenWrt / ImmortalWrt), a small x86 or ARM mini-PC, a Raspberry Pi, a VPS. On macOS / Windows you can build it and run `probe`, nothing else. |
| A node to connect to | REALITY (VLESS + `xtls-rprx-vision`), or plain VLESS + TLS (what most commercial providers offer). VLESS only — Trojan / VMess / Shadowsocks are not supported. |
| A way to route traffic into it | Either you point clients at its SOCKS5 port by hand, or a transparent nft rule hands it the traffic. |

If you have one server with both a good route and a clean IP, use it directly; the chaining machinery buys you nothing. See the decision section at the top of [the chaining tutorial](chain-relay-exit.zh-CN.md).

**What it is not**: not a GUI client, no subscriptions, no automatic latency testing, no load balancing, no log level switch (every connection logs its lifecycle to stderr). Those are outside the design goals.

## 2. Running in five minutes (SOCKS5)

### 2.1 Pick the right binary

Every tagged release carries five static musl binaries. No shared libraries, nothing to install:

| File | Target |
|---|---|
| `zray-mipsel-softfloat` | Little-endian MIPS — most MT7621 / MT7620 routers (Xiaomi AC2100, Redmi AC2100, Newifi 3, ...) |
| `zray-mips-softfloat` | Big-endian MIPS, a few older boxes |
| `zray-arm-v7` | ARMv7: most Qualcomm / Broadcom A7 routers, Raspberry Pi 2/3 |
| `zray-aarch64` | ARM64: Raspberry Pi 4, ARM mini-PCs, ARM VPS |
| `zray-x86_64` | Any PC / x86 mini-PC / x86 VPS |

`uname -m` prints `mips` for both MIPS endiannesses, so it cannot tell you which one you have. On OpenWrt ask the distro instead:

```sh
. /etc/openwrt_release && echo $DISTRIB_ARCH
# mipsel_24kc / mips_24kc / aarch64_generic / arm_cortex-a7_neon-vfpv4 / x86_64
```

`mipsel*` → `zray-mipsel-softfloat`, `mips_*` → `zray-mips-softfloat`, everything else maps by the table. `opkg print-architecture` prints the same string.

The builds are soft-float because the routers this targets have no FPU. A soft-float binary still runs on a box with one, just without using it.

### 2.2 Download, verify, put it somewhere permanent

```sh
mkdir -p /mnt/zray
cd /mnt/zray
wget -O zray https://github.com/yunnysunny/zray/releases/latest/download/zray-mipsel-softfloat
wget -O zray.sha256 https://github.com/yunnysunny/zray/releases/latest/download/zray-mipsel-softfloat.sha256
chmod 755 zray
sha256sum zray      # compare by eye with the first column of zray.sha256
./zray              # no config yet: "cannot read config.json" means the binary runs
```

> Apart from a config path, `zray` takes **no arguments**: no `-h`, no `--version`. `zray --help` is treated as a file name. The version is the first field of the first startup log line.

Do not leave it in `/tmp` (wiped on reboot); `/mnt/zray` on OpenWrt survives reboots.

### 2.3 Write a minimal config

A REALITY node, one outbound:

```json
{
  "listen": "127.0.0.1:1080",
  "server": "server host or IP",
  "port": 443,
  "sni": "camouflage site",
  "security": "reality",
  "public_key": "server publicKey (base64url)",
  "short_id": "server shortId (empty if none)",
  "uuid": "your uuid",
  "max_connections": 64
}
```

Everything else has a default; see [config.example.json](../config.example.json). Two hard rules:

- **An unknown key is a startup error** (`bad config: UnknownField`). A trailing comma or a misspelled key is never silently ignored.
- `security` is explicit. `"reality"` requires `public_key`; `"tls"` rejects `public_key` / `short_id`. A wrong combination fails at startup instead of quietly downgrading to unverified TLS.

Size `max_connections` from the memory you have (about 93 KiB per slot, see section 6).

### 2.4 Run it in the foreground and read the log

```sh
cd /mnt/zray && ./zray config.json
```

A healthy start prints two lines — version, inbounds and slots first, then the outbound and the mode in force:

```
zray 0.4.0 socks5 [127.0.0.1:1080] redirect [] sniff true, 1 outbounds, 0 rules, 64 slots x 93 KiB = 5937 KiB
outbound -: server:443 sni camouflage mode reality (short_id -) vision
```

`mode reality` means REALITY. `mode tls, verify NONE -- WARNING: ...` means you are on a plain VLESS+TLS node with no certificate verification: anyone on the path can impersonate it.

### 2.5 Prove it actually works

From the same machine (or anything that can reach that SOCKS5 port):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

`ip=` should be the server's egress address and `loc=` its country code. A second check that DNS goes through the tunnel too:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ipinfo.io/json
```

Once both work, point a client at it: SwitchyOmega, a sing-box socks outbound, any phone SOCKS5 client — address `router-ip:1080`.

> The SOCKS5 inbound has **no authentication**. Keep `listen` on `127.0.0.1`; if you must expose it to the LAN, `0.0.0.0:1080` works, but anyone on that network can use it as an exit.

## 3. Where the values come from: share links

Providers and self-hosted panels hand out a `vless://` link. Its fields map one-to-one onto the config:

```
vless://<uuid>@<host>:<port>?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=<public key>&sid=ab12&type=tcp&flow=xtls-rprx-vision#name
```

| In the link | Config key | Notes |
|---|---|---|
| uuid before `@` | `uuid` | |
| host / port after `@` | `server` / `port` | hostname or literal IP |
| `security=reality` | `"security": "reality"` | |
| `security=tls` | `"security": "tls"` + `"tls_verify": "none"` | the latter is mandatory in this version |
| `pbk=` | `public_key` | base64url, copy verbatim |
| `sid=` | `short_id` | hex, up to 8 bytes; empty if absent |
| `sni=` | `sni` | REALITY camouflage site, must match the server |
| `fp=chrome` | none | the fingerprint is always Chrome; it cannot be changed |
| `flow=xtls-rprx-vision` | `flow` | the default on `tcp`, so it can be omitted |
| `encryption=none` | none | VLESS is always none |
| `type=tcp` | none | the default |
| `type=ws` | `"network": "ws"` | with `path=` → `ws_path`, `host=` → `ws_host` |

That link becomes:

```json
{
  "listen": "127.0.0.1:1080",
  "server": "host",
  "port": 443,
  "sni": "example.com",
  "security": "reality",
  "public_key": "<pbk value>",
  "short_id": "ab12",
  "uuid": "<uuid>",
  "flow": "xtls-rprx-vision"
}
```

**Not supported / watch out for:**

- `type=grpc`, `type=httpupgrade`, `type=quic`: not implemented. `tcp` and `ws` only.
- WebSocket **early data** (`ed=2048` and friends in the link): not implemented. Do not put it into `ws_path`; if the server sends early data alongside the 101, the connection dies with `WsEarlyData`. Most servers do not send it unless the client asks.
- `fp` other than chrome (`firefox`, `safari`, `randomized`): the client only presents a Chrome fingerprint; setting something else does nothing, and a server that gates on fingerprint will refuse the connection.
- Subscriptions: zray does not read them. Expand the node into its fields yourself.
- "Same name, many landings, pick the fastest": out of scope. `rules` only splits by domain suffix, there is no latency testing.

## 4. Three ways to deploy

### 4.1 Local / LAN SOCKS5 (simplest)

What section 2 sets up. Good for one machine or a handful of devices, and for validating a node before touching transparent proxying.

UDP rides SOCKS5 `UDP ASSOCIATE`, wrapped in XUDP (VLESS mux), matching what xray does for Vision. Two limits: **Vision TCP outbounds only** (a ws outbound carries no UDP), and **payloads above roughly 600 bytes may be dropped by the server's outbound** (DNS works, QUIC generally does not). Fragmentation is not supported; no real client uses it.

### 4.2 Transparent proxy (the router is the gateway)

Goal: LAN devices need no configuration, matching traffic enters the tunnel by itself.

1. **Configure two inbounds.** Keep `listen` for debugging; `redirect` is what nft feeds:

```json
{
  "listen": "127.0.0.1:10800",
  "redirect": "0.0.0.0:1080",
  "sniff": true,
  "server": "server host or IP",
  "port": 2443,
  "bootstrap_dns": "223.5.5.5",
  "...": "the rest as before"
}
```

2. **Redirect matching destinations to the `redirect` port.** A typical domain-based split: the DNS side (dnsmasq + chinadns-ng, or smartdns) writes the IPs of matched domains into an nft set, and this table forwards them:

```
table inet gfw {
    set iplist { type ipv4_addr; flags interval; }
    chain prerouting { type nat hook prerouting priority 0;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
    chain output     { type nat hook output priority filter;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
}
```

`prerouting` covers other devices, `output` covers the router itself. `redirect` relies on `SO_ORIGINAL_DST`, so the port here is zray's `redirect` port (`1080` above), never `listen`.

3. **Two traps that must be avoided:**

- **The server's own IP must never land in that set.** Otherwise zray's connection to its server is redirected back into zray — a loop whose symptom is a healthy start, then instant slot exhaustion and a log full of failures. Exclude it with `ip daddr != <server IP>`, or put the server hostname on the direct list in the DNS side.
- **Whatever resolves `server` must not depend on the tunnel.** If dnsmasq / chinadns-ng forwards DoT through zray, both wait for each other at boot and neither starts. Set `bootstrap_dns` to a public resolver (e.g. `223.5.5.5`) so the startup lookup bypasses the local resolver entirely.

4. **Leave `sniff` on.** A transparent inbound only sees the destination IP; `sniff` extracts the TLS SNI or HTTP `Host` from the first client bytes and swaps the IP for the name. When the target IP could match a `rules` entry, zray waits up to one second for that sniff — that second is expected.

5. **Verify** from another LAN machine with no proxy configured:

```sh
curl https://www.cloudflare.com/cdn-cgi/trace      # ip= should be the server egress
curl https://www.baidu.com                          # should still work (not in the set)
```

### 4.3 Several nodes, domain routing, chaining

For when "a machine with a good route" and "a machine with a clean IP" are different boxes: `rules` send a few domains to a group of exits, everything else stays on `default`.

```json
{
  "outbounds": [
    { "tag": "relay", "server": "...", "security": "reality", "public_key": "...", "uuid": "..." },
    { "tag": "exit-a", "server": "...", "security": "tls", "tls_verify": "none",
      "uuid": "...", "network": "ws", "ws_path": "/vless-ws", "flow": "none", "dialer": "relay" }
  ],
  "rules": [
    { "domain_suffix": ["openai.com", "chatgpt.com", "claude.ai"], "outbound": ["exit-a"] }
  ],
  "default": ["relay"]
}
```

Rules worth knowing: `outbound` is a **group**, and failover (`fail_backoff_s`, 30 s by default) only rotates inside that group; a matched rule **never falls back to `default`**. That is deliberate — better a failed request than a request that was supposed to leave from the clean IP going out somewhere else. The full mechanics, encapsulation layers, costs and verification live in [the chaining tutorial](chain-relay-exit.zh-CN.md) (Chinese).

## 5. Run it as a service

### 5.1 OpenWrt: the procd script in the repo

```sh
scp zray              root@router:/mnt/zray/zray
scp config.json       root@router:/mnt/zray/config.json
scp deploy/zray.init  root@router:/etc/init.d/zray
ssh root@router '
  chmod 755 /etc/init.d/zray /mnt/zray/zray
  chmod 600 /mnt/zray/config.json
  /etc/init.d/zray enable
  /etc/init.d/zray start
  sleep 2; logread | tail -5
'
```

`deploy/zray.init` does three things: `procd_set_param command` runs `/mnt/zray/zray /mnt/zray/config.json`, `respawn 3600 5 0` restarts it after a crash (and gives up if it crashes five times within 5 s), and stdout / stderr are handed to logd. Live log: `logread -f`.

Keep the config at mode `600` (it holds the `uuid` and `public_key`) and the binary at `755`.

### 5.2 Plain Linux: systemd

The repo does not ship a unit file; this one works as-is:

```ini
# /etc/systemd/system/zray.service
[Unit]
Description=zray REALITY/VLESS client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/zray/zray /etc/zray/config.json
Restart=always
RestartSec=3
LimitNOFILE=1024
# only if the redirect inbound listens on a privileged port:
# AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now zray
journalctl -u zray -f
```

Transparent-proxy nft / iptables rules are yours to persist (`nft -f /etc/nftables.conf` or your distro's mechanism); zray does not install them.

## 6. Tuning: spend the scarce CPU and RAM well

### 6.1 Memory: `max_connections` × 93 KiB

The tail of the startup line is the ledger: `64 slots x 93 KiB = 5937 KiB`. Slots are allocated **once at startup** and do not grow with traffic; when they run out, new connections are refused (`conn table full`).

| Scenario | Estimate |
|---|---|
| Plain SOCKS5 / transparent | concurrent connections × 93 KiB |
| Chained (`dialer`) | × 2: each chained connection holds two slots (client side + hop) |
| 128 MB router (~20 MB free) | 32–64 slots is a sensible range |

64 slots ≈ 5.8 MB, 128 slots ≈ 11.6 MB. Start at 64; raise it when you see `conn table full`, and stop when raising it triggers the OOM killer.

### 6.2 TCP window: `tcp_rmem` (matters more than any zray option)

On a 128 MB router the default `net.ipv4.tcp_rmem` ceiling is about 930 KB, capping one stream at roughly window / RTT — about 1 MB/s at 190 ms. On the reference box, raising the ceiling to 4 MB lifted HTTPS through the tunnel from ~1 MB/s to 9–10 MB/s:

```sh
echo 'net.ipv4.tcp_rmem = 4096 131072 4194304' > /etc/sysctl.d/99-zray.conf
sysctl -p /etc/sysctl.d/99-zray.conf
```

Do **not** reach for zray's `sock_buf` here: it disables the kernel's window autotuning and is clamped by `net.core.rmem_max`. Leave `sock_buf` at `0`.

### 6.3 Timeouts

| Key | Default | When to change it |
|---|---|---|
| `connect_timeout_s` | 5 | raise to 8–10 if a slow cross-border + ws handshake occasionally times out |
| `handshake_timeout_s` | 15 | inbound side: waiting for the client to finish SOCKS5 and send a request; relax on mobile networks |
| `idle_timeout_s` | 600 | cuts long-lived connections such as phone push; raise to 1800 if pushes stall |

`connect_timeout_s` must be ≥ 1; 0 is a startup error.

### 6.4 Things not to do

- **Prefer Vision nodes.** A `flow: "none"` or ws node keeps the outer TLS for the whole connection, and a single MIPS core tops out around 1–1.5 MB/s doing software AES-GCM.
- **Keep `default` on a Vision node**; send only the few domains that need a clean IP to a ws exit.
- **Keep the REALITY server's domain out of gfwlist** (section 4.2, trap 3).

## 7. Troubleshooting

Everything goes to stderr — `logread` on OpenWrt, `journalctl` on systemd. Find your symptom:

| Symptom | Cause | Fix |
|---|---|---|
| `bad config: UnknownField` | a misspelled or extra key | compare against [config.example.json](../config.example.json) character by character; a `"..."` placeholder is an unknown key too |
| `bad config: use either top-level server/uuid or outbounds, not both` | both forms present | pick one |
| `bad config: connect_timeout_s must be >= 1` | set to 0 | set ≥ 1 |
| `cannot resolve <host>: ...` | startup resolution failed | check the network; set `bootstrap_dns` when the local resolver depends on the tunnel; `bootstrap_dns` only asks for A records, so an AAAA-only host needs the system resolver |
| `CertificateRejected` | router clock not synced (REALITY checks the timestamp sealed in `session_id`), or `public_key` / `short_id` / `uuid` mismatch | sync first (`ntpd -q -p pool.ntp.org`, check `date`), then re-check the parameters |
| `conn table full` | slots exhausted: too much concurrency, or an unreachable upstream holding a slot per connection until the timeout | raise `max_connections`; check upstream reachability |
| healthy start, then instant failures and exhausted slots | the transparent inbound redirects the connection to the server itself | exclude the server IP from the nft set |
| transparent proxy does nothing | rule not matching / port set to `listen` / `sniff` off / client gateway+DNS not pointed at the router | walk through 4.2 |
| IP-only sites work, domains do not | DNS not routed correctly, or `sniff` off so names never reach the rules | fix DNS splitting; keep `sniff: true` |
| ws node is slow (< 1 MB/s) | ws cannot use Vision; the whole connection is software-encrypted — it is CPU, not the line | expected; use it for chat-sized traffic only |
| chain failure log `... -> relay side` | the router never got through to the relay (or the relay's own handshake did not finish) | check the relay and your home uplink |
| chain failure log `... -> exit side` | the relay is up, the exit never replied or the handshake failed | check exit address / port / uuid / ws_path, and whether the relay's egress is allowed by the exit |
| chain failure log `hop connection never accepted` | the relay side never accepted the local hop SOCKS connection | usually a `dialer` pointing at the wrong node |
| `WsUpgradeRejected` | the upgrade returned something other than 101 (usually 404) | `ws_path` / `ws_host` do not match the server |
| `WsEarlyData` | the server sent early data in the same record as the 101 | turn early data off on the server; keep `ed=` out of `ws_path` |
| `tls alert handshake_failure` / intermittent `CertificateRejected` | `sni` does not match the server certificate or REALITY config | re-check `sni` |
| no UDP, QUIC fails | only Vision TCP outbounds carry UDP, and payloads > ~600 bytes may be dropped by the server | known limit; browsers fall back to TCP |
| phone push stalls or drops | `idle_timeout_s` closes long-lived connections | raise `idle_timeout_s` |

A general way to tell whose problem it is: run `probe` (section 9) straight at the server. `probe` works but zray does not → the problem is zray's config or inbound. Neither works → the problem is the server or the path.

## 8. Upgrading from v0.3

0.4.0 adds the VLESS WebSocket transport (`network: "ws"`), outbound chaining (`dialer`), domain-suffix routing (`rules` / `default`), in-group failover (`fail_backoff_s`) and a hard per-attempt deadline (`connect_timeout_s`).

Upgrading is a binary swap:

```sh
/etc/init.d/zray stop
# overwrite /mnt/zray/zray, keep the config
/etc/init.d/zray start
```

Configs stay backward compatible: a top-level `server` / `uuid` config keeps working, `connect_timeout_s` defaults to 5 s. Two things to keep in mind:

- Once you start chaining, raise `max_connections` to twice the connection count (two slots per chained connection).
- Before 0.4, `handshake_timeout_s` covered the upstream attempts too; now it is inbound-only and upstreams have their own 5 s deadline.

## 9. The two bundled test tools

### 9.1 `probe`: check a server directly

Does one real handshake and one proxied request without starting the service. Builds and runs anywhere, Windows and macOS included:

```sh
zig build probe -- <ip> <port> <sni> <public_key> [short_id|-] [uuid url]

zig build probe -- 203.0.113.5 443 example.com K5Ko4T...4G8 - \
    00000000-0000-0000-0000-000000000000 https://www.cloudflare.com/
```

The output shows the cipher suite and key-exchange group the REALITY server chose, whether the certificate HMAC verified, and the bytes received through the tunnel. Point the URL at `https://tls.peet.ws/api/all` to see the fingerprint the inner connection presents.

### 9.2 `udptest.py`: check UDP

```sh
python3 tools/udptest.py 127.0.0.1 1080
```

Sends a few DNS queries over SOCKS5 `UDP ASSOCIATE` to exercise the XUDP path. Needs Python 3, no third-party packages.

## Feedback

Config errors name the offending key and the reason; when asking for help, paste the two startup log lines together with the error — far more useful than "it does not connect". Issues: <https://github.com/yunnysunny/zray/issues>.

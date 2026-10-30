# zray

[English](../README.md) | 简体中文

面向家用路由器的最小 [REALITY](https://github.com/XTLS/REALITY) 客户端
（VLESS + `xtls-rprx-vision`），用 Zig 编写，除 Zig 标准库外没有任何依赖。

它针对的是这样的设备：一两个慢核心、约 100 MB 内存、没有 FPU。单线程、
`epoll` 事件循环、启动时一次性分配固定数量的连接槽位。内存占用在启动时就
确定，不随流量增长。

参考部署：小米 AC2100（MT7621，MIPS 1004Kc，软浮点，ImmortalWrt 23.05）——
静态二进制 802 KB，64 个槽位时虚拟内存 7.3 MB、RSS 约 2.2 MB。在这台机器上
经隧道连接日本的 REALITY 服务器（RTT 约 110 ms）拉取 50 MB 的实测：

| 路径                                  | 吞吐 | zray CPU（单个 1004Kc 线程） |
|---------------------------------------|-----:|-----------------------------:|
| HTTPS，Vision 已切到 direct 直拷        | 9–10 MB/s | 约 17 %                 |
| HTTP，留在外层 TLS 内（软算 AES-GCM）   | 1.5 MB/s | 约 98 %                  |
| 3 路 HTTPS 并发                        | 合计 10 MB/s | 约 55 %              |

同一主机不走隧道、由 WAN 直连只有 1.4 MB/s，慢的是运营商的国际出口。走隧道的
HTTPS 受服务器链路限制；HTTP 无法脱离外层 TLS，受 CPU 限制——这颗核软算
AES-GCM 的上限约 1.5 MB/s，这正是 Vision 的 direct 直拷在这类设备上有意义的原因。

这类设备有一个内核参数需要留意：128 MB 内存下 `net.ipv4.tcp_rmem` 的默认上限
约 930 KB，单条流的吞吐被限制在大约“窗口 / RTT”，190 ms 时约 1 MB/s。把上限
调高（例如在 `/etc/sysctl.d/` 里写 `net.ipv4.tcp_rmem = 4096 131072 4194304`）
之后，上表的 HTTPS 数字才从约 1 MB/s 提升到现在的水平。不要用 `sock_buf` 来
解决这个问题：它会关掉内核的自动调优，而且会被 `net.core.rmem_max` 截断。

![mir 上的吞吐实测](images/throughput-mir.png)

## 功能

- **TLS 1.3 客户端**：基于 `std.crypto` 从零实现——密钥调度、记录层、握手
  状态机、证书签名校验。与 RFC 8448 逐字节对照验证。
- **REALITY 认证**：对服务器公钥做临时 X25519，HKDF 派生 auth key，AEAD 封装
  `session_id`，HMAC-SHA512 校验证书。
- **Chrome TLS 指纹**：cipher suites / groups / key share / versions / extensions
  均带 GREASE，15 个 Chrome 套件，扩展顺序逐连接随机，GREASE ECH、ALPS、
  `compress_certificate`、X25519MLKEM768 混合密钥交换。JA4 的 `_b`、`_c` 段
  与当前 Chrome 一致。
- **VLESS + XTLS Vision**：填充状态机，内层 TLS 1.3 握手完成后切到直接拷贝，
  大流量不做二次加密。
- **入口**：SOCKS5（CONNECT 与 UDP ASSOCIATE）、透明 netfilter `REDIRECT`
  （`SO_ORIGINAL_DST`）。
- **UDP** 走 XUDP（VLESS mux），full-cone，与 xray 对 Vision 的处理一致。
- **零延迟嗅探**：上游握手还在飞的时候，客户端的首包已经到了，顺手解出
  TLS SNI 或 HTTP `Host`，让服务端看到域名而不是 IP。

刻意不做的：TLS 1.2、会话恢复、0-RTT、证书解压（只 *offer*
`compress_certificate`，Go 服务端不会真用）、TPROXY、SOCKS5 UDP 分片。

## 构建

需要 Zig 0.17.0。每个 tag 发布都附带 mipsel / mips / aarch64 / armv7 / x86_64
的预编译二进制（全部静态 musl）；CI 对每次 push 都会构建（见
.github/workflows/）。

```sh
zig build test                                   # 单元测试（本机）
zig build --release                              # 本机二进制 -> zig-out/bin/zray

# 交叉编译到路由器
zig build --release -Dtarget=mipsel-linux-musl -Dcpu=mips32r2+soft_float -p zig-out/mipsel
zig build --release -Dtarget=aarch64-linux-musl -p zig-out/aarch64
zig build --release -Dtarget=x86_64-linux-musl  -p zig-out/x86_64
```

`--release` 对应 `ReleaseSmall`。代理服务只在 Linux 上运行；下面的 probe
可在任何平台运行。

### Probe

`probe` 不启动服务，只做一次真实握手和一次经隧道的 HTTP(S) 请求。用来检查
服务端配置、查看协商结果：

```sh
zig build probe -- <ip> <port> <sni> <public_key> [short_id|-] [uuid url]

zig build probe -- 203.0.113.5 443 example.com K5Ko4T...4G8 - \
    00000000-0000-0000-0000-000000000000 https://www.cloudflare.com/
```

输出包含 REALITY 服务端选的套件和密钥交换组、证书 HMAC 是否通过、经隧道
收到的字节数。把 URL 指向 `https://tls.peet.ws/api/all` 可以看到内层连接呈现
的指纹。

## 配置

`zray [config.json]`（默认 `./config.json`）。参见
[config.example.json](../config.example.json)。

| 字段 | 默认 | 含义 |
|---|---|---|
| `listen` | `127.0.0.1:1080` | SOCKS5 入口。`""` 关闭。 |
| `redirect` | `""` | 接 `REDIRECT` 规则的透明入口。`""` 关闭。`listen` / `redirect` 至少设一个。 |
| `sniff` | `true` | 有 TLS SNI / HTTP Host 时用它替换目标 IP。 |
| `server` | — | 上游服务器域名或 IP（REALITY 或普通 VLESS+TLS）。启动时解析一次。 |
| `port` | `443` | |
| `bootstrap_dns` | `""` | 启动时用来解析 `server` 的 DNS 服务器（`ip` 或 `ip:port`），直接走 UDP 查询，绕过 `/etc/resolv.conf`。本地解析器自身要经过隧道时设置它，避免开机时两个服务互相等待。失败时回退到系统解析器。 |
| `sni` | 同 `server` | ClientHello 里的 SNI（伪装站点）。 |
| `public_key` | `""` | 服务端 `publicKey`（base64url，与分享链接一致）。留空则改用普通 VLESS+TLS，不做 REALITY 认证。 |
| `short_id` | `""` | 十六进制，最多 8 字节。 |
| `uuid` | — | VLESS 用户 id。 |
| `max_connections` | `128` | 连接槽位数。每个槽位约 92 KiB，启动时分配。 |
| `handshake_timeout_s` | `15` | TCP 连接 + TLS 握手的总时限。 |
| `idle_timeout_s` | `600` | 双向都无流量多久后关闭。 |
| `sock_buf` | `0` | 每个 socket 的 `SO_SNDBUF` / `SO_RCVBUF`；`0` 用内核默认。 |

REALITY 服务端会校验客户端时钟（封在 `session_id` 里的时间戳）。路由器时间
没同步时所有握手都会以 `CertificateRejected` 失败。

### 普通 VLESS + TLS（非 REALITY）

`public_key` 留空（或省略）时，客户端发起标准 TLS 1.3 握手：`session_id` 填
随机数、不带 REALITY 的认证扩展、不校验证书链（等同 `allowInsecure`），因此
可以用来连普通机场 / 自建的 VLESS + `xtls-rprx-vision` over TLS 节点。此模式
下 `short_id` 无意义，`sni` 必须填成服务端证书对应的域名。REALITY 的
`compress_certificate` 扩展不会发出，避免对端用本客户端不支持的方式压缩证书。

## 部署到 OpenWrt

[deploy/](../deploy/) 下有 procd init 脚本和配置模板。

```sh
scp zig-out/mipsel/bin/zray root@router:/mnt/zray/zray
scp config.json             root@router:/mnt/zray/config.json
scp deploy/zray.init        root@router:/etc/init.d/zray
ssh root@router 'chmod 755 /etc/init.d/zray /mnt/zray/zray; chmod 600 /mnt/zray/config.json;
                 /etc/init.d/zray enable; /etc/init.d/zray start'
```

透明代理需要一条 nft（或 iptables）`redirect` 规则把流量送到 `redirect`
端口。典型的按域名分流方案是：DNS 解析器把命中的域名解析出的 IP 写进 nft
集合，再配一条这样的规则：

```
table inet gfw {
    set iplist { type ipv4_addr; flags interval; }
    chain prerouting { type nat hook prerouting priority 0;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
    chain output     { type nat hook output priority filter;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
}
```

务必保证 REALITY 服务器自己的 IP 永远不会进这个集合，并且用来解析 `server`
的解析器本身不依赖这条隧道。如果它确实依赖（比如 chinadns-ng 或 dnsmasq 的
DoT 上游走 zray），把 `bootstrap_dns` 设成一个公共 DNS，启动时的解析就完全
不经过本地解析器。

## 目录结构

```
src/
  main.zig            配置、监听器、epoll 主循环
  probe.zig           一次性握手 / 请求测试器
  tls/
    hello.zig         ClientHello 序列化
    key_schedule.zig  TLS 1.3 密钥调度（SHA-256 / SHA-384）
    record.zig        记录层、AEAD、逐记录 nonce
    handshake.zig     握手消息重组与解析
    signature.zig     CertificateVerify 签名校验
    client.zig        sans-I/O 握手状态机（X25519、X25519MLKEM768）
    reality.zig       REALITY 认证：session_id 封装、证书 HMAC
    fingerprint.zig   Chrome ClientHello 参数
    testdata/         RFC 8448 向量（脚本生成）
  proxy/
    vless.zig         VLESS 请求 / 响应头
    vision.zig        XTLS Vision 填充状态机
    mux.zig           XUDP（Mux.Cool）帧
    socks5.zig        SOCKS5 greeting / CONNECT / UDP ASSOCIATE
    sniff.zig         TLS SNI 与 HTTP Host 提取
  linux/
    sys.zig           系统调用薄封装（socket、epoll、SO_ORIGINAL_DST）
    conn.zig          单连接状态机与中继
deploy/               OpenWrt procd 脚本与配置模板
tools/udptest.py      SOCKS5 UDP ASSOCIATE 冒烟测试
```

`tls/` 和 `proxy/` 全部是 sans-I/O 且有单元测试（`zig build test`）；
只有 `linux/` 碰 socket。

## 状态与已知限制

- `server` 只在启动时解析一次，IP 变了需要重启。还没有连接失败退避。
  见 [TODO.md](../TODO.md)。
- UDP 载荷超过约 600 字节时可能被服务端出口丢弃；DNS 正常，QUIC 一般不通。
- 没有日志级别控制，每条连接的生命周期都打到 stderr。

## 许可证

[MIT](../LICENSE)。

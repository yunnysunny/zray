# zray

[English](../README.md) | 简体中文

面向家用路由器的最小 [REALITY](https://github.com/XTLS/REALITY) 客户端
（VLESS + `xtls-rprx-vision`），用 Zig 编写，除 Zig 标准库外没有任何依赖。

它针对的是这样的设备：一两个慢核心、约 100 MB 内存、没有 FPU。默认单线程、
可配置多个 `epoll` 网络 worker、启动时一次性分配固定数量的连接槽位。内存占用在启动时就
确定，不随流量增长。

参考部署：小米 AC2100（MT7621，MIPS 1004Kc，软浮点，ImmortalWrt 23.05）——
静态二进制 802 KB，64 个槽位时虚拟内存 7.3 MB、RSS 约 2.2 MB。在这台机器上
经隧道连接 RTT 约 110 ms 的 REALITY 服务器拉取 50 MB 的实测：

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
- **WebSocket 传输、链式与分流**：节点可以骑在 TLS 里的 `network: "ws"` 上；
  一个出站可以经另一个拨出（`dialer`）；`domain_suffix` 规则把域名分给一组
  出口，故障只在组内切换。

刻意不做的：TLS 1.2、会话恢复、0-RTT、证书解压（只 *offer*
`compress_certificate`，Go 服务端不会真用）、TPROXY、SOCKS5 UDP 分片。

## 构建

需要 Zig 0.17.0。每个 tag 发布都附带 mipsel / mips / aarch64 / armv7 / x86_64
的预编译二进制（全部静态，不依赖 libc）；CI 对每次 push 都会构建（见
.github/workflows/）。

```sh
zig build test                                   # 单元测试（本机）
zig build --release                              # 本机二进制 -> zig-out/bin/zray

# 交叉编译到路由器
zig build --release -Dtarget=mipsel-linux-musl -Dcpu=mips32r2+soft_float -p zig-out/mipsel
zig build --release -Doptimize=fast -Dtarget=aarch64-linux-musl -p zig-out/aarch64
zig build --release -Doptimize=fast -Dtarget=x86_64-linux-musl  -p zig-out/x86_64
```

`--release` 对应 `ReleaseSmall`；加 `-Doptimize=fast` 改为 `ReleaseFast`，用户态加解密（ws / 非 Vision 的 TLS）快 2–3 倍，代价是体积更大。发布包中 aarch64 和 x86_64 使用 `ReleaseFast`，mips 和 armv7 使用 `ReleaseSmall`。代理服务只在 Linux 上运行；下面的 probe
可在任何平台运行。

aarch64 和 x86_64 另外提供硬件加密版本，TLS 使用 CPU 的 AES / 无进位乘法指令，加密流量快数倍。在不支持这些指令的 CPU 上会直接以 `Illegal instruction` 崩溃，下载前先看 `/proc/cpuinfo`：

| 二进制 | 适用条件 | 典型 CPU |
|---|---|---|
| `zray-aarch64-crypto` | `Features` 含 `aes pmull sha2` | Amlogic S905/S912、瑞芯微 RK3328/RK3399、大多数 ARMv8 盒子 |
| `zray-aarch64` | 其他情况 | 树莓派 4（BCM2711） |
| `zray-x86_64-aes` | `flags` 含 `sse4_2 popcnt aes pclmulqdq avx` | Intel N100/N200/N305、二代及以后酷睿，AMD GX-412（APU2）、锐龙/EPYC |
| `zray-x86_64` | 其他情况 | Intel J4125、N5105、J3455、J1900（无 AVX）、Core 2 |

```sh
grep -m1 -o -w -E 'aes|pmull|sha2' /proc/cpuinfo | sort -u                  # ARM
grep -m1 -o -w -E 'sse4_2|popcnt|aes|pclmulqdq|avx' /proc/cpuinfo | sort -u    # x86
```

自行构建：

```sh
zig build --release -Doptimize=fast -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53+aes+sha2 -p zig-out/aarch64-crypto
zig build --release -Doptimize=fast -Dtarget=x86_64-linux-musl -Dcpu=x86_64_v2+aes+pclmul+avx -p zig-out/x86_64-aes
```

默认静态构建（`-Ddynamic=false`）。传入 `-Ddynamic=true` 可改为动态链接
目标系统的 C 标准库；该选项也适用于 `run`、`probe` 和 `test`：

```sh
zig build --release -Ddynamic=true
zig build test -Ddynamic=true
# OpenWrt：复用路由器上的 musl 共享库
zig build --release -Dtarget=mipsel-linux-musleabi -Dcpu=mips32r2+soft_float -Ddynamic=true -p zig-out/mipsel-dynamic
```

动态版要求目标设备提供匹配的 libc 和动态加载器，包括相同的架构与软硬浮点 ABI。
MIPS musl 动态构建的软浮点 ABI 使用 `musleabi`，硬浮点使用 `musleabihf`。

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
[config.example.json](../config.example.json)（REALITY）和
[config.example.tls.json](../config.example.tls.json)（普通 TLS）。

| 字段 | 默认 | 含义 |
|---|---|---|
| `listen` | `127.0.0.1:1080` | SOCKS5 入口。`""` 关闭。 |
| `redirect` | `""` | 接 `REDIRECT` 规则的透明入口。`""` 关闭。`listen` / `redirect` 至少设一个。 |
| `sniff` | `true` | 有 TLS SNI / HTTP Host 时用它替换目标 IP。 |
| `server` | — | 上游服务器域名或 IP（REALITY 或普通 VLESS+TLS）。启动时解析一次。 |
| `port` | `443` | |
| `bootstrap_dns` | `""` | 启动时用来解析 `server` 的 DNS 服务器（`ip` 或 `ip:port`），直接走 UDP 查询，绕过 `/etc/resolv.conf`。本地解析器自身要经过隧道时设置它，避免开机时两个服务互相等待。失败时回退到系统解析器。 |
| `sni` | 同 `server` | ClientHello 里的 SNI（伪装站点）。 |
| `security` | `"reality"` | `"reality"` 或 `"tls"`（普通 VLESS+TLS，见下文）。 |
| `public_key` | — | 服务端 `publicKey`（base64url，与分享链接一致）。`security = "reality"` 时必填，`"tls"` 时不允许出现。 |
| `short_id` | `""` | 十六进制，最多 8 字节。仅 REALITY。 |
| `tls_verify` | — | 仅 `security = "tls"` 时使用，且必填。目前只实现了 `"none"`（不校验证书，等同 `allowInsecure`）；`"ca"`、`"pin"` 预留，暂时会被拒绝。 |
| `uuid` | — | VLESS 用户 id。 |
| `max_connections` | `128` | 连接槽位数。每个槽位约 92 KiB，启动时分配。 |
| `handshake_timeout_s` | `15` | 入站侧时限：SOCKS5 握手、选定上游之前等待客户端。 |
| `connect_timeout_s` | `5` | 单次上游尝试（TCP 连接、hop SOCKS、TLS、WS 升级）的硬时限，有流量也不延长；超时即换组内下一个成员。 |
| `idle_timeout_s` | `600` | 双向都无流量多久后关闭。 |
| `sock_buf` | `0` | 每个 socket 的 `SO_SNDBUF` / `SO_RCVBUF`；`0` 用内核默认。 |
| `stats_interval_s` | `60` | 统计输出间隔，单位秒；0 关闭定期统计。 |
| `workers` | `1` | 网络 worker 数：1 保持原有单事件循环；0 自动选择、最多 4 个；2..16 指定数量，实际不超过 max_connections。 |
| `crypto_backend` | `"off"` | 内核 AES-GCM 后端：off / auto / afalg / devcrypto；auto 依次尝试 devcrypto、AF_ALG、软件实现。 |
| `crypto_min_bytes` | `4096` | 提交后端的 AEAD 明文字节数下限，含该值；小于该值时使用软件实现。 |
| `crypto_max_bytes` | `32768` | 提交后端的 AEAD 明文字节数上限，含该值；大于该值时使用软件实现。 |

上述运行参数全部写在配置 JSON 的**最外层**，与 `listen`、`max_connections`
同级；使用多节点时也不要写进 `outbounds` 的节点对象。省略字段即采用表中默认值。
修改实际启动命令使用的文件后，需要重启进程才生效。

直接运行：`zray /path/to/config.json`。仓库的 OpenWrt init 脚本读取
`/mnt/zray/config.json`；按该方式部署时修改此文件，然后执行
`/etc/init.d/zray restart`。JSON 不支持注释，布尔值使用 `true` / `false`。

REALITY 服务端会校验客户端时钟（封在 `session_id` 里的时间戳）。路由器时间
没同步时所有握手都会以 `CertificateRejected` 失败。

### 多核与转发配置

`workers` 是网络事件循环数。默认 `1` 在主线程运行原有的单事件循环；
设为 `0` 时自动选择、最多 4 个；设为 `2` 到 `16` 时指定数量，实际数量
不超过 `max_connections`。例如四核机器可以设置 `"workers": 4`。
`max_connections` 始终是整个进程的连接总额度，不会乘以 worker 数。
每条连接归属于一个 worker，多核用于处理并发连接，不会把一条 TCP 流拆给多个核心。

splice 默认启用，无需配置开关。在对应方向进入 Vision direct 且旧缓冲区排空后，
通过 `socket → 内核 pipe → socket` 转发。源端不支持 splice 或 pipe 分配失败时，
会在消费源数据之前自动回退普通转发。数据不进入用户缓冲区，进程仍负责 syscall、
epoll、背压和关闭；内层 TLS 加密保留。已有配置中的 `splice` 字段请删除，
否则会因未知字段导致启动报错。

`stats_interval_s` 默认 `60`，可设为 `10` 每十秒查看一次累计统计，
或设为 `0` 关闭定期统计。它不控制其他连接日志。

### 内核加密后端与阈值

`crypto_backend` 默认 `"off"`，不会调用内核加密接口。可选值：

| 模式 | 行为 |
|---|---|
| `off` | 使用原有软件加密。 |
| `afalg` | 使用 AF_ALG 的通用 `gcm(aes)` 算法。 |
| `devcrypto` | 使用 `/dev/crypto` 的 AES-GCM 接口。 |
| `auto` | 依次尝试 devcrypto、AF_ALG，不可用时回退软件实现。 |

例如把 `"crypto_backend": "off"` 改为 `"crypto_backend": "auto"` 即可启用。
支持 AES-128/256-GCM，ChaCha20 保持软件实现。具体实现由内核选择，接口成功
不代表一定使用硬件，也不保证提速。每个新会话先校验加密、解密和错误标签处理；
后端不可用时回退软件，认证标签失败则拒绝记录。

`crypto_min_bytes` 和 `crypto_max_bytes` 分别是单个 AEAD 请求的明文字节数
下限与上限，**两个边界都包含**。默认 `4096..32768`，必须满足
`1 <= crypto_min_bytes <= crypto_max_bytes <= 32768`，否则启动报错。
例如下限改为 `8192`，只有至少 8192 字节的请求才提交后端。
计量包含 TLS 内层内容、content-type 字节和 padding，不包含 record 头、标签和 AAD。
不会合并记录来凑阈值；下限高于实际 record 大小时，该记录继续使用软件实现。
Vision direct 的大块数据不再经过外层 TLS 加密，因此这些阈值不作用于该直传数据。

环境变量 `ZRAY_CRYPTO_BACKEND` 可覆盖 JSON 的模式，取值同上。例如：

```sh
ZRAY_CRYPTO_BACKEND=afalg zray /path/to/config.json
```

如果配置里设成 `off` 仍发现后端启用，检查启动环境是否设置了此变量。
修改模式、阈值或 worker 数后都需要重启。

### 加密后端与 worker 数

每个网络 worker 使用独立的加密上下文，同步执行后端请求。后端会话在首个
符合条件的请求到来时打开并自检，接口或算法不可用时回退软件实现。

`workers: 4`、`crypto_backend: "auto"` 使用 4 个网络 worker（包含主线程），
前提是总连接额度不少于 4。`workers: 1` 时由主线程运行单个事件循环。
Vision direct 流量绕过外层 TLS record 加密。

`crypto_kernel` 统计成功的内核接口操作，`crypto_fallback` / `crypto_badmac`
分别统计回退和认证失败。内核操作计数不能证明实际硬件使用率。

### 完整 REALITY 配置示例

下面展示四个网络 worker 的完整配置。必须替换 `server`、`sni`、`public_key`、
`uuid`，并按服务端设置填写 `short_id`；占位值不能直接用于连接。
示例保持内核加密关闭；测试后端时把 `crypto_backend` 改为上述模式之一。

```json
{
  "listen": "127.0.0.1:1080",
  "server": "node.example.com",
  "port": 443,
  "sni": "example.com",
  "security": "reality",
  "public_key": "<填入服务端公钥，base64url>",
  "short_id": "",
  "uuid": "00000000-0000-0000-0000-000000000000",
  "flow": "xtls-rprx-vision",
  "max_connections": 64,
  "workers": 4,
  "stats_interval_s": 60,
  "crypto_backend": "off",
  "crypto_min_bytes": 4096,
  "crypto_max_bytes": 32768
}
```

### 普通 VLESS + TLS（非 REALITY）

```json
{
  "security": "tls",
  "tls_verify": "none",
  "server": "node.example.com",
  "uuid": "00000000-0000-0000-0000-000000000000"
}
```

`security = "tls"` 时，客户端发起标准 TLS 1.3 握手：`session_id` 填随机数、
不带 REALITY 的认证扩展；`tls_verify = "none"` 时不校验证书链（等同
`allowInsecure`），因此可以用来连普通机场 / 自建的 VLESS + `xtls-rprx-vision`
over TLS 节点。此模式下不能出现 `public_key` 和 `short_id`，`sni` 必须填成服务端
证书对应的域名。REALITY 的 `compress_certificate` 扩展不会发出，避免对端用本
客户端不支持的方式压缩证书。

模式不会自动推断：REALITY 配置里 `public_key` 缺失或键名拼错会在启动时直接
报错，而不是悄悄变成普通 TLS；配置里出现未知键也会报错。启动日志会打印当前
模式。

**风险。** `tls_verify = "none"` 接受任何证书。链路上的任何一方（不可信的
Wi-Fi、运营商中间设备、上游被入侵的路由器）都可以冒充服务器，拿到 VLESS
`uuid`，并读取或篡改隧道内的全部流量。只在可信链路上使用，或者在接受该风险的
前提下使用。路由器通常没有可用的 CA 证书链（`opkg install ca-bundle` 可以装
一个），所以后续计划实现 CA 校验（`"ca"`）和 SPKI 固定（`"pin"`）作为更安全
的选项。

### 多节点、WebSocket、链式代理与按域名分流

单个节点仍用顶层的 `server` / `uuid`。多个节点时改用 `outbounds`（不要与
顶层 `server` / `uuid` 同时出现）。每个节点除原有字段外还有：

| 字段 | 默认 | 含义 |
|---|---|---|
| `tag` | `""` | `dialer`、`rules`、`default` 引用的名字。 |
| `network` | `"tcp"` | `"tcp"` 或 `"ws"`（TLS 里的 VLESS WebSocket）。 |
| `ws_path` | `"/"` | Upgrade 路径，仅 `network` 为 `"ws"` 时使用。 |
| `ws_host` | 同 `sni` | Upgrade 请求的 `Host`。 |
| `flow` | tcp 为 vision，ws 为 `"none"` | `"xtls-rprx-vision"` 或 `"none"`。WebSocket 上的 Vision 会被拒绝。 |
| `dialer` | `""` | 必须是排在前面的某个节点的 `tag`。本节点的 TCP 经该节点拨出，用来把干净出口挂在中继后面。 |
| `bootstrap_dns` | 顶层的值 | 可按节点覆盖。 |

`rules` 按顺序匹配。`domain_suffix` 是 ASCII 后缀（`example.com` 匹配自身和
`a.example.com`，不匹配 `notexample.com`），`outbound` 是该组的 tag 列表。
`default` 是都不匹配时使用的组，默认第一个节点。`fail_backoff_s`（默认 30）
是某个成员连接失败后被跳过的秒数；只在**同一组**内换下一个，命中的规则不会
退回到别的组或 `default`。切换只会换到不在 backoff 期的成员；组内全部处于
backoff 时，每条连接只探测一次，失败即断开。最多 16 个节点。UDP 只走带 Vision 的 TCP 节点。
目标是 IP 且可能命中规则时，最多等 1 秒嗅探 SNI / Host，否则用 `default`。
示例见 [config.example.routing.json](../config.example.routing.json)。

#### WebSocket 和链式在小路由器上的代价

在上面那台 MT7621 上实测（单线程，每次只跑一个 20–30 MB 下载，relay 与它之间 RTT 约 110 ms）。
“每 MB CPU”是 zray 自身每传 1 MB 消耗的 CPU 时间。

| 路径 | 吞吐 | 每 MB CPU |
|---|---|---|
| 单个 REALITY + Vision 节点 | 5–7 MB/s | 0.03–0.05 s |
| 链式，relay 和 exit 都是 REALITY + Vision | 1.2–6 MB/s | 0.10–0.15 s（约 3 倍） |
| 单个 `network: "ws"` 节点（TLS，无 Vision） | 约 0.5 MB/s | 0.65–1.0 s（15–30 倍） |
| 链式，Vision relay → ws exit | 约 0.55 MB/s | 约 1.0 s |

- Vision 在内层 TLS 建立后让 zray 不再加解密，所以每字节几乎不花 CPU。`ws` 节点
  （以及任何 `flow: "none"` 的节点）整条连接都要保留外层 TLS，MIPS 核心要用软件
  加解密每一个字节。按每 MB 1 秒算，即使线路够快，单核也就 1–1.5 MB/s 左右（上表
  约 0.5 MB/s 的上限在节点，不在 CPU）。ws 出口适合 AI 聊天这类小流量，不适合下载
  和视频；`default` 应保持在 Vision 节点上。
- relay 用 Vision 的链式额外加密很少，但每个字节要在本机回环 hop 上多走两趟，这就
  是第二行约 3 倍的来源。
- 每条链式连接占**两个**槽位（客户端那条和它的 hop 连接），每个约 93 KiB。
  `max_connections` 要按并发链式连接数的两倍估算，并且不超过路由器的空闲内存
  （启动日志会打印 `N slots x 93 KiB`）。空闲内存只有 20 MB 左右的机器，32–64
  个槽位比较合适。
- 链式节点失败时，日志会指出是哪一段的问题，例如
  `outbound exit-a failed: connect timeout; relay up, no reply from exit -> exit side`
  或 `...; relay TCP connect pending -> relay side`。无论哪一段出问题，backoff
  都记在链式节点本身。
- hop 监听绑定在 `127.0.0.1` 的随机端口上，没有认证：本机任何进程都能把它当成
  经 dialer 节点出去的 SOCKS 代理。在路由器上通常只有 zray 自己会连它。

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

## 文档

- [usage.zh-CN.md](usage.zh-CN.md) —— 使用说明：五分钟上手、分享链接怎么填、
  三种部署方式、调优、排错表、从 v0.3 升级。（[English](usage.md)）
- [chain-relay-exit.zh-CN.md](chain-relay-exit.zh-CN.md) —— 链式出站教程：
  relay 和 exit 到底在干什么，封装层次与代价。
- [../website/](../website/) —— 官方网站（纯静态，无构建步骤）。

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
    ws.zig            WebSocket 客户端帧处理（VLESS 的 `ws` 传输）
  linux/
    sys.zig           系统调用薄封装（socket、epoll、SO_ORIGINAL_DST）
    conn.zig          单连接状态机与中继
deploy/               OpenWrt procd 脚本与配置模板
tools/udptest.py      SOCKS5 UDP ASSOCIATE 冒烟测试
website/              官方网站（纯静态，无构建步骤）
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
